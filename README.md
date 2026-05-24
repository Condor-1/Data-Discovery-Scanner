# Sensitive Data Discovery Scanner

A lightweight Python CLI tool for scanning folders and projects for exposed sensitive
information and script safety warnings.

This project is a static analysis utility. It is not antivirus software, malware
detection, or a sandbox. It reports suspicious patterns so developers can review
files before running code or publishing repositories.

## Planned Features

- Detect likely API keys, passwords, tokens, emails, secrets, and credentials.
- Warn on suspicious `.bat`, `.cmd`, and `.ps1` script patterns.
- Scan supported programming, config, text, and script files recursively.
- Read files line by line for memory-friendly scanning.
- Skip common generated/vendor folders and binary files.
- Report severity, file path, line number, finding type, and masked preview.

## Supported File Types

Programming:

- `.py`, `.java`, `.c`, `.cpp`, `.js`, `.ts`, `.go`, `.rs`, `.php`, `.sh`

Configs and text:

- `.env`, `.json`, `.yaml`, `.yml`, `.ini`, `.cfg`, `.xml`, `.toml`, `.txt`, `.md`, `.log`

Scripts:

- `.bat`, `.cmd`, `.ps1`

## Project Layout

```text
src/sensitive_data_scanner/
  cli.py                 CLI entry point.
  scanner.py             Main scan orchestration.
  findings.py            Finding and severity models.
  config.py              Supported extensions and ignored directories.
  detection/
    patterns.py          Sensitive data regex rules.
    script_warnings.py   Script safety warning rules.
    masking.py           Masked preview helpers.
  io/
    file_walker.py       Recursive file discovery and filtering.
    text_reader.py       Safe line-by-line text reading.
  reporting/
    console.py           Human-readable CLI output.
```

## Development Status

Initial folder structure is in place. Implementation will be built section by section.

