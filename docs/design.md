# Design Notes

## Goal

Build a lightweight CLI scanner that helps identify exposed sensitive information
and suspicious script patterns inside folders or projects.

## Non-Goals

- Antivirus engine
- Malware classification
- Sandboxing
- AI detection
- Cloud integrations
- GUI or dashboard
- Live process monitoring

## Scanner Flow

1. Parse CLI arguments through `sdscan`.
2. Validate that the target path exists.
3. Walk the target directory recursively.
4. Ignore noisy folders such as `.git`, `node_modules`, `venv`, `dist`, and `build`.
5. Keep only supported text-like extensions.
6. Read each file line by line.
7. Run sensitive-data rules on supported files.
8. Run script-warning rules on `.bat`, `.cmd`, and `.ps1` files.
9. Emit findings with severity, file path, line number, finding type, and masked preview.

## Module Responsibilities

- `cli.py` parses commands such as `sdscan scan ./folder`.
- `scanner.py` coordinates file discovery, text reading, detection, and finding creation.
- `findings.py` defines the `Finding` result model.
- `config.py` stores supported extensions and ignored directory names.
- `io/file_walker.py` recursively returns file paths while skipping ignored directories.
- `io/text_reader.py` streams files line by line with tolerant UTF-8 decoding.
- `io/file_type.py` decides whether a file type should be scanned.
- `detection/patterns.py` detects likely API keys, passwords, tokens, emails, and secrets.
- `detection/script_warnings.py` detects suspicious script behavior.
- `detection/masking.py` hides sensitive values before terminal display.
- `reporting/console.py` prints findings, colors, warnings, and summary counts.
- `reporting/json.py` prints machine-readable scan results and summaries.

## Supported Findings

Sensitive-data rules currently detect:

- Possible API keys
- Possible passwords
- Possible tokens
- Email addresses
- Possible secrets

Script-warning rules currently detect:

- Eval-style execution
- Suspicious download commands
- Encoded PowerShell
- Hidden PowerShell
- Dangerous system or user-folder deletion commands
- Hardcoded credentials inside scripts

## Finding Philosophy

Findings should be useful, not noisy. Rules should prefer high-confidence patterns
and warnings should avoid claiming that a script is malicious.

Sensitive values are kept in memory as raw findings so future integrations can use
them, but console output masks them by default.

## CLI Behavior

- `sdscan --version` prints the installed tool version.
- `sdscan scan ./folder` scans a file or folder.
- `sdscan scan ./folder --format json` prints machine-readable JSON.
- `sdscan scan ./folder --quiet` prints only a compact result.
- Exit code `0` means the scan completed with no findings.
- Exit code `1` means the scan completed and findings were detected.
- Exit code `2` means the command or target path was invalid.
