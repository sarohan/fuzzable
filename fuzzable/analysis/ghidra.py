"""
ghidra.py

    Ghidra-based binary analysis backend using pyhidra for headless analysis.
"""
import os
import sys
import typing as t
from pathlib import Path

from . import AnalysisBackend, AnalysisException, Fuzzability, DEFAULT_SCORE_WEIGHTS
from ..metrics import CallScore
from ..log import log

# Workaround: skcriteria (imported via fuzzable.analysis above) incorrectly
# deletes importlib.metadata after use (see skcriteria/__init__.py line 59).
# Re-import it here to restore the attribute before pyhidra needs it.
# Note: We must explicitly assign since `import X.Y` doesn't re-add Y as an
# attribute of X when Y is already in sys.modules.
import importlib
import importlib.metadata as _importlib_metadata
importlib.metadata = _importlib_metadata  # restore deleted attr


def _setup_pyhidra_path() -> None:
    """Add third_party/pyhidra to sys.path if needed."""
    pyhidra_path = Path(__file__).parent.parent.parent / "third_party" / "pyhidra"
    if pyhidra_path.exists() and str(pyhidra_path) not in sys.path:
        sys.path.insert(0, str(pyhidra_path))


def _patch_pyhidra_setup_project() -> None:
    """
    Monkey-patch pyhidra's _setup_project to handle NotFoundException.

    pyhidra only catches IOException when opening a project, but Ghidra throws
    NotFoundException when the project directory exists but the .gpr file is missing.
    """
    import pyhidra.core as pyhidra_core
    from pathlib import Path
    from typing import Tuple, Optional, Union

    # Store original to avoid re-patching
    if hasattr(pyhidra_core._setup_project, '_patched'):
        return

    original_setup_project = pyhidra_core._setup_project

    def patched_setup_project(
        binary_path,
        project_location=None,
        project_name=None,
        language=None,
        compiler=None,
        loader=None
    ):
        from ghidra.base.project import GhidraProject
        from ghidra.util.exception import NotFoundException
        from java.io import IOException
        from jpype import JClass

        if binary_path is not None:
            binary_path = Path(binary_path)
        if project_location:
            project_location = Path(project_location)
        else:
            project_location = binary_path.parent
        if not project_name:
            project_name = f"{binary_path.name}_ghidra"
        project_location /= project_name
        project_location.mkdir(exist_ok=True, parents=True)

        if isinstance(loader, str):
            from java.lang import ClassLoader, ClassNotFoundException
            try:
                gcl = ClassLoader.getSystemClassLoader()
                loader = JClass(loader, gcl)
            except (TypeError, ClassNotFoundException) as e:
                raise ValueError from e

        if isinstance(loader, JClass):
            from ghidra.app.util.opinion import Loader
            if not Loader.class_.isAssignableFrom(loader):
                raise TypeError(f"{loader} does not implement ghidra.app.util.opinion.Loader")

        # Open/Create project - THIS IS THE FIX: catch NotFoundException too
        program = None
        try:
            project = GhidraProject.openProject(project_location, project_name, True)
            if binary_path is not None:
                if project.getRootFolder().getFile(binary_path.name):
                    program = project.openProgram("/", binary_path.name, False)
        except (IOException, NotFoundException):
            project = GhidraProject.createProject(project_location, project_name, False)

        if binary_path is not None and program is None:
            if language is None:
                if loader is None:
                    program = project.importProgram(binary_path)
                else:
                    program = project.importProgram(binary_path, loader)
                if program is None:
                    raise RuntimeError(f"Ghidra failed to import '{binary_path}'. Try providing a language manually.")
            else:
                from ghidra.program.util import DefaultLanguageService
                from ghidra.program.model.lang import LanguageID, LanguageNotFoundException, CompilerSpecID, CompilerSpecNotFoundException
                try:
                    service = DefaultLanguageService.getLanguageService()
                    lang = service.getLanguage(LanguageID(language))
                except LanguageNotFoundException:
                    raise ValueError("Invalid Language ID: " + language)

                if compiler is None:
                    comp = lang.getDefaultCompilerSpec()
                else:
                    try:
                        comp = lang.getCompilerSpecByID(CompilerSpecID(compiler))
                    except CompilerSpecNotFoundException:
                        raise ValueError(f"Invalid CompilerSpecID: {compiler} for Language: {lang.getLanguageID().toString()}")

                if loader is None:
                    program = project.importProgram(binary_path, lang, comp)
                else:
                    program = project.importProgram(binary_path, loader, lang, comp)
                if program is None:
                    message = f"Ghidra failed to import '{binary_path}'. "
                    if compiler:
                        message += f"The provided language/compiler pair ({language} / {compiler}) may be invalid."
                    else:
                        message += f"The provided language ({language}) may be invalid."
                    raise ValueError(message)
            project.saveAs(program, "/", program.getName(), True)

        return project, program

    patched_setup_project._patched = True
    pyhidra_core._setup_project = patched_setup_project


class GhidraAnalysis(AnalysisBackend):
    """Analysis backend using Ghidra via pyhidra for headless binary analysis."""

    def __init__(
        self,
        target: Path,
        include_sym: t.List[str] = [],
        include_nontop: bool = False,
        skip_sym: t.List[str] = [],
        skip_stripped: bool = False,
        score_weights: t.List[float] = DEFAULT_SCORE_WEIGHTS,
    ):
        # Check GHIDRA_INSTALL_DIR environment variable
        if not os.environ.get("GHIDRA_INSTALL_DIR"):
            raise RuntimeError(
                "GHIDRA_INSTALL_DIR environment variable not set. "
                "Please set it to your Ghidra installation directory."
            )

        # Setup pyhidra import path
        _setup_pyhidra_path()

        try:
            import pyhidra
        except ImportError as e:
            raise ImportError(
                f"Failed to import pyhidra: {e}. "
                "Ensure jpype1 is installed: uv add jpype1"
            ) from e

        # Start Ghidra JVM if not already started
        if not pyhidra.started():
            log.debug("Starting Ghidra via pyhidra...")
            pyhidra.start()

        # Apply patch for NotFoundException handling (must be after JVM starts)
        _patch_pyhidra_setup_project()

        # Ensure absolute path for binary (pyhidra requires this)
        target = Path(target).resolve()

        # Open the binary with Ghidra
        log.debug(f"Opening binary {target} with Ghidra")
        self._flat_api_context = pyhidra.open_program(target, analyze=True)
        self.flat_api = self._flat_api_context.__enter__()
        self.program = self.flat_api.getCurrentProgram()
        self.function_manager = self.program.getFunctionManager()
        self.listing = self.program.getListing()

        super().__init__(
            self.program,
            include_sym,
            include_nontop,
            skip_sym,
            skip_stripped,
            score_weights,
        )

        # Cache for BasicBlockModel (lazy-loaded)
        self._bb_model = None

    def __del__(self):
        """Cleanup: close the Ghidra project when done."""
        if hasattr(self, "_flat_api_context") and self._flat_api_context:
            try:
                self._flat_api_context.__exit__(None, None, None)
            except Exception:
                pass

    @property
    def bb_model(self):
        """Lazy-loaded BasicBlockModel for CFG analysis."""
        if self._bb_model is None:
            from ghidra.program.model.block import BasicBlockModel

            self._bb_model = BasicBlockModel(self.program)
        return self._bb_model

    def __str__(self) -> str:
        return "ghidra"

    def run(self) -> Fuzzability:
        log.debug("Iterating over functions")

        # Get iterator over all functions (forward=True for ascending address order)
        functions = self.function_manager.getFunctions(True)

        for func in functions:
            name = func.getName()
            addr = str(func.getEntryPoint())

            # Skip already-visited functions (handles duplicates)
            if name in self.visited:
                continue
            self.visited.append(name)

            log.debug(f"Checking if we should ignore {name}")
            if self.skip_analysis(func):
                log.warning(f"Skipping {name} from fuzzability analysis.")
                self.skipped[name] = addr
                continue

            log.debug(f"Checking if {name} is a top-level call")
            if not self.include_nontop and not self.is_toplevel_call(func):
                log.warning(
                    f"Skipping {name} (not top-level) from fuzzability analysis."
                )
                self.skipped[name] = addr
                continue

            log.info(f"Starting analysis for function {name}")
            score = self.analyze_call(name, func)
            self.scores.append(score)

        if len(self.scores) == 0:
            raise AnalysisException(
                "No suitable function symbols filtered for analysis."
            )

        return super()._rank_fuzzability(self.scores)

    def analyze_call(self, name: str, func: t.Any) -> CallScore:
        """
        Analyze a single Ghidra Function and return a CallScore.

        Args:
            name: Function name
            func: ghidra.program.model.listing.Function object
        """
        # Ghidra uses "FUN_" prefix for stripped symbols
        stripped = name.startswith("FUN_") or name.startswith("sub_")
        addr = str(func.getEntryPoint())

        # Check fuzz-friendly name patterns (skip if stripped)
        fuzz_friendly = 0
        if not stripped:
            log.debug(f"{name} - checking if fuzz friendly")
            fuzz_friendly = GhidraAnalysis.is_fuzz_friendly(name)

        return CallScore(
            name=name,
            loc=addr,
            toplevel=self.is_toplevel_call(func),
            fuzz_friendly=fuzz_friendly,
            risky_sinks=self.risky_sinks(func),
            natural_loops=self.natural_loops(func),
            coverage_depth=self.get_coverage_depth(func),
            cyclomatic_complexity=self.get_cyclomatic_complexity(func),
            stripped=stripped,
        )

    def skip_analysis(self, func: t.Any) -> bool:
        """
        Determine if a function should be skipped from analysis.

        Args:
            func: ghidra.program.model.listing.Function object
        """
        name = func.getName()

        # Call parent class check (handles global ignores, explicit include/skip)
        if super().skip_analysis(name):
            return True

        # Skip thunk functions (wrappers to external calls)
        if func.isThunk():
            return True

        # Skip external/imported functions
        if func.isExternal():
            return True

        return False

    def is_toplevel_call(self, target: t.Any) -> bool:
        """
        Check if function has no callers (is a top-level entry point).

        Args:
            target: ghidra.program.model.listing.Function object
        """
        from ghidra.util.task import TaskMonitor

        # getCallingFunctions returns Set<Function> of callers
        calling_functions = target.getCallingFunctions(TaskMonitor.DUMMY)
        return calling_functions.isEmpty()

    def risky_sinks(self, func: t.Any) -> int:
        """
        Count callsites to risky functions within this function.

        Args:
            func: ghidra.program.model.listing.Function object
        """
        log.debug(f"{func.getName()} - checking for risky sinks")

        from ghidra.util.task import TaskMonitor

        risky_sinks = 0

        # Get all functions called by this function
        called_functions = func.getCalledFunctions(TaskMonitor.DUMMY)

        for callee in called_functions:
            callee_name = callee.getName()
            if GhidraAnalysis._is_risky_call(callee_name):
                risky_sinks += 1

        return risky_sinks

    def get_coverage_depth(self, target: t.Any) -> int:
        """
        Calculate coverage depth via DFS on the call graph.

        Args:
            target: ghidra.program.model.listing.Function object
        """
        log.debug(f"{target.getName()} - getting coverage depth")

        from ghidra.util.task import TaskMonitor

        depth = 0
        visited_local = set()
        callstack = [target]

        while callstack:
            func = callstack.pop()
            func_name = func.getName()

            if func_name in visited_local:
                continue

            visited_local.add(func_name)
            depth += 1

            # Add callees to callstack
            called_functions = func.getCalledFunctions(TaskMonitor.DUMMY)
            for callee in called_functions:
                callee_name = callee.getName()
                if callee_name not in visited_local and callee_name not in self.visited:
                    callstack.append(callee)

        return depth

    def natural_loops(self, func: t.Any) -> int:
        """
        Count natural loops by analyzing the basic block model.

        A natural loop exists when a back edge goes from a block to one
        of its dominators (detected as edge pointing to earlier address).

        Args:
            func: ghidra.program.model.listing.Function object
        """
        log.debug(f"{func.getName()} - getting number of natural loops")

        from ghidra.util.task import TaskMonitor

        loop_count = 0

        # Get code blocks for this function
        code_block_iterator = self.bb_model.getCodeBlocksContaining(
            func.getBody(), TaskMonitor.DUMMY
        )

        blocks = []
        while code_block_iterator.hasNext():
            blocks.append(code_block_iterator.next())

        # For each block, check if any successor points back (back edge)
        for block in blocks:
            dest_iterator = block.getDestinations(TaskMonitor.DUMMY)
            while dest_iterator.hasNext():
                dest_ref = dest_iterator.next()
                dest_addr = dest_ref.getDestinationAddress()
                # Check if this is a back edge (pointing to earlier address in function)
                if func.getBody().contains(dest_addr):
                    if dest_addr.compareTo(block.getMinAddress()) < 0:
                        loop_count += 1

        return loop_count

    def get_cyclomatic_complexity(self, func: t.Any) -> int:
        """
        Calculate cyclomatic complexity: CC = Edges - Nodes + 2

        Args:
            func: ghidra.program.model.listing.Function object
        """
        log.debug(f"{func.getName()} - calculating cyclomatic complexity")

        from ghidra.util.task import TaskMonitor

        # Count basic blocks (nodes)
        code_block_iterator = self.bb_model.getCodeBlocksContaining(
            func.getBody(), TaskMonitor.DUMMY
        )

        num_blocks = 0
        num_edges = 0

        while code_block_iterator.hasNext():
            block = code_block_iterator.next()
            num_blocks += 1

            # Count outgoing edges
            dest_iterator = block.getDestinations(TaskMonitor.DUMMY)
            while dest_iterator.hasNext():
                dest_iterator.next()
                num_edges += 1

        # CC = E - N + 2
        return max(1, num_edges - num_blocks + 2)
