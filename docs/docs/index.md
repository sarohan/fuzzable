# Fuzzable

Framework for Automating _Fuzzable_ Target Discovery with Static Analysis

## Overview

Vulnerability researchers conducting security assessments on software will often harness the capabilities of coverage-guided fuzzing through powerful tools like AFL++ and libFuzzer. However, when encountering large and complex codebases or closed-source binaries, researchers have to painstakingly dedicate time to manually audit and reverse engineer them to identify functions where fuzzing-based exploration can be useful.

**Fuzzable** is a framework that integrates both with C/C++ source code and binaries to assist vulnerability researchers in identifying function targets that are viable for fuzzing. This is done by applying several static analysis-based heuristics to pinpoint risky behaviors in the software and the functions that execute them.

## Installation

### Quick Install

```bash
# with pip
pip install fuzzable

# with uv
uv add fuzzable
```

### With Ghidra Support

```bash
# with pip
pip install fuzzable[ghidra]

# with uv
uv add fuzzable[ghidra]
```

### Development Build

```bash
git clone --recursive https://github.com/ex0dus-0x/fuzzable
cd fuzzable/

# with uv (recommended)
uv sync

# with Ghidra support
uv sync --extra ghidra
```

## Disassembly Backends

Fuzzable supports multiple disassembly backends for binary analysis, with the following priority order:

### 1. Binary Ninja

[Binary Ninja](https://binary.ninja) is the primary backend due to its excellent analysis capabilities, including signature matching and function identification from inlining.

**Setup**: Install the Binary Ninja API for standalone headless usage:

```bash
python3 /Applications/Binary\ Ninja.app/Contents/Resources/scripts/install_api.py
```

### 2. Ghidra

[Ghidra](https://ghidra-sre.org/) is a free and open-source reverse engineering tool developed by the NSA. Fuzzable integrates with Ghidra via [pyhidra](https://github.com/dod-cyber-crime-center/pyhidra).

**Setup**:

1. Install Ghidra from [https://ghidra-sre.org/](https://ghidra-sre.org/)

2. Set the `GHIDRA_INSTALL_DIR` environment variable:
   ```bash
   export GHIDRA_INSTALL_DIR=/path/to/ghidra
   ```

3. Install fuzzable with Ghidra support:
   ```bash
   pip install fuzzable[ghidra]
   ```

### 3. angr

[angr](https://angr.io) serves as the fallback backend when neither Binary Ninja nor Ghidra are available. It is open-source and requires no additional setup.

## Usage

### Analyzing Binaries

```bash
# Analyze a shared object library
fuzzable analyze examples/binaries/libbasic.so

# Analyze with specific backend (if multiple are available)
fuzzable analyze target.so
```

### Analyzing Source Code

```bash
# Analyze a single C source file
fuzzable analyze examples/source/libbasic.c

# Analyze a workspace with multiple C/C++ files
fuzzable analyze examples/source/source_bundle/
```

### Exporting Reports

```bash
# Export as JSON
fuzzable analyze --export=report.json target.so

# Export as CSV
fuzzable analyze --export=report.csv target.so

# Export as Markdown
fuzzable analyze --export=report.md target.so
```

### Harness Generation

```bash
# Generate a harness from a candidate function
fuzzable create-harness target --symbol-name=some_unsafe_call
```

## Static Analysis Heuristics

Fuzzable uses several weighted heuristics to determine fuzzability:

| Heuristic             | Description                                                 | Weight |
|-----------------------|-------------------------------------------------------------|--------|
| Fuzz Friendly Name    | Symbol name implies behavior that ingests file/buffer input | 0.3    |
| Risky Sinks           | Arguments that flow into risky calls (ie memcpy)            | 0.3    |
| Natural Loops         | Number of loops detected with the dominance frontier        | 0.05   |
| Cyclomatic Complexity | Complexity of function target based on edges + nodes        | 0.05   |
| Coverage Depth        | Number of callees the target traverses into                 | 0.3    |

You can customize these weights using the `--score-weights` argument:

```bash
fuzzable analyze target.so --score-weights=0.2,0.2,0.2,0.2,0.2
```

## Binary Ninja Plugin

Fuzzable can be installed through the Binary Ninja plugin marketplace:

1. Go to `Binary Ninja > Manage Plugins`
2. Search for "fuzzable"
3. Install the plugin

## Contributing

- Create an [issue](https://github.com/ex0dus-0x/fuzzable/issues) for feature requests or bugs
- Submit a [pull request](https://github.com/ex0dus-0x/fuzzable/pulls) for fixes and enhancements

## License

Fuzzable is licensed under the [MIT License](https://codemuch.tech/license.txt).
