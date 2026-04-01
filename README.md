# DS Store Recovery

Recover file and directory structures from exposed `.DS_Store` metadata using either:

- URL mode (`--url`): recursively fetches `.DS_Store` references and downloads available files.
- Local mode (`--local`): recursively scans local `.DS_Store` files and rebuilds structure, copying known local file contents.

## Why this exists

macOS Finder can create `.DS_Store` files that contain directory metadata (entry names, layout metadata, and related records). If those files are accidentally exposed on web servers, attackers can enumerate hidden paths and attempt direct downloads.

This project helps with:

- Security validation and red-team simulation.
- Incident response and exposure triage.
- Lab reconstruction and controlled forensic workflows.

## Installation

### Editable install (recommended for development)

```bash
pip install -e .
```

This installs dependencies automatically and creates the command:

```bash
ds-store-recovery --help
```

## Usage

### URL mode

```bash
ds-store-recovery \
  --url https://example.com/.DS_Store \
  --output ./recovered
```

Optional URL mode controls:

- `--threads` worker threads (default: `10`)
- `--timeout` per-request timeout in seconds (default: `10`)
- `--retries` retry count for transient failures (default: `2`)
- `--max-requests` hard cap to prevent runaway crawling (default: `10000`)
- `--log-level` logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`)

Example:

```bash
ds-store-recovery \
  --url https://example.com/.DS_Store \
  --output ./recovered \
  --threads 20 \
  --timeout 15 \
  --retries 3 \
  --max-requests 5000 \
  --log-level INFO
```

### Local mode

```bash
ds-store-recovery \
  --local ~/Documents/TestingNotes/HTTP \
  --output ./recovered-local
```

By default, if `.DS_Store` lists a file name but the actual local file is missing, the tool creates an empty placeholder. To disable placeholders:

```bash
ds-store-recovery \
  --local ~/Documents/TestingNotes/HTTP \
  --output ./recovered-local \
  --no-placeholders
```

## Notes and limitations

- `.DS_Store` does not contain full file contents, only metadata and names.
- URL mode can only download files that are directly accessible over HTTP(S).
- Local mode can only copy file contents when those files actually exist in the local source directory.
- Some `.DS_Store` internals rely on library behavior and can vary across macOS versions.

## Documentation

- [What this is, why it works, and prevention guidance](docs/ds_store_disclosure.md)

## Development and testing

Install development dependencies:

```bash
pip install -e .[dev]
```

Run tests:

```bash
pytest
```

GitHub Actions CI is included in `.github/workflows/ci.yml` and runs the test suite on Python 3.10-3.13.

## Legal and ethical use

Use this tool only on systems you own or have explicit authorization to test.
