# Sensitive Data Discovery Scanner(SDScan)

Lightweight CLI utility for detecting sensitive data exposure in files and directories

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Features

- Regex-based sensitive data detection
- Recursive directory scanning
- Script safety warnings
- Masked output previews
- Cross-platform CLI support

---

## Supported File Types

Programming:

- `.py`, `.java`, `.c`, `.cpp`, `.js`, `.ts`, `.go`, `.rs`, `.php`, `.sh`

Configs and text:

- `.env`, `.json`, `.yaml`, `.yml`, `.ini`, `.cfg`, `.xml`, `.toml`, `.txt`, `.md`, `.log`

Scripts:

- `.bat`, `.cmd`, `.ps1`

---

## Project Layout


```text
src/sensitive_data_scanner/
├── cli.py              # CLI entry point
├── scanner.py          # Scan orchestration
├── findings.py         # Finding models
├── config.py           # Extensions and exclusions
│
├── detection/
│   ├── patterns.py     # Regex detection rules
│   └── script_warnings.py
│
├── io/
│   ├── file_walker.py
│   └── text_reader.py
│
└── reporting/
    └── console.py      # CLI output formatting
```

---

## Development Status

The version 0.1.0 is published and ready to use

---

## Installation Guide

SDScan is currently installable directly from the GitHub repository.

### Windows(Powershell):

```powershell
git clone https://github.com/Condor-1/Data-Discovery-Scanner.git
cd Data-Discovery-Scanner
python -m pip install -e .
sdscan --version
```

### MacOS/Linux:

```bash
git clone https://github.com/Condor-1/Data-Discovery-Scanner.git
cd Data-Discovery-Scanner
python3 -m pip install -e .
sdscan --version
```

### After Installation:

Scan the examples forlder to test: 

```bash
sdscan scan ./examples
 ```

#### For Windows:

```Powershell
sdscan scan "C:\path\to\folder"
```

#### For MacOS/Linux:

```bash
sdscan scan /path/to/folder
```

---

## Future Plans

Planning to publish this to PyPi to make installation easier.