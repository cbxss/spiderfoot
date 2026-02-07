# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Run Commands

```bash
# Setup
uv venv && uv sync                              # Create venv and install deps
uv pip install ".[dev]"                          # Install with dev deps

# Run web UI
python sf.py -l 127.0.0.1:5001

# Run CLI scan
python sf.py -s example.com -m sfp_dnsresolve -o tab

# Lint
python -m flake8 . --count --show-source --statistics

# Run all tests (lint + pytest, excludes module integration tests)
./test/run

# Run pytest only
python -m pytest -n auto --dist loadfile --ignore=test/integration/modules/ .

# Run a single test file
python -m pytest test/unit/test_spiderfoot.py

# Run a single test
python -m pytest test/unit/test_spiderfoot.py::TestSpiderFoot::test_some_method

# Module integration tests (require API keys)
python -m pytest test/integration/modules/
```

## Architecture

SpiderFoot is an OSINT automation tool with 238 scanner modules. It has two interfaces: a CherryPy web UI (`sfwebui.py`) and a CLI (`sf.py`).

### Core Classes

- **`SpiderFoot`** (`sflib.py`) — Main orchestrator. Handles HTTP requests, DNS resolution, proxy config, target parsing, and module coordination.
- **`SpiderFootScanner`** (`sfscan.py`) — Controls individual scan execution. Spawned as a separate process per scan. Manages module lifecycle and event routing.
- **`SpiderFootPlugin`** (`spiderfoot/plugin.py`) — Base class for all modules. Provides queue-based event handling, threading via `SpiderFootThreadPool`, and logging.
- **`SpiderFootEvent`** (`spiderfoot/event.py`) — Immutable-style data object representing discovered information. Has `eventType`, `data`, `module`, `confidence`, `visibility`, `risk`, and a `sourceEvent` parent link forming a discovery chain.
- **`SpiderFootTarget`** (`spiderfoot/target.py`) — Represents the scan target. Valid types: `IP_ADDRESS`, `IPV6_ADDRESS`, `INTERNET_NAME`, `EMAILADDR`, `HUMAN_NAME`, `BGP_AS_OWNER`, `PHONE_NUMBER`, `USERNAME`, `BITCOIN_ADDRESS`, `NETBLOCK_OWNER`, `NETBLOCKV6_OWNER`.
- **`SpiderFootDb`** (`spiderfoot/db.py`) — SQLite layer with WAL mode and thread-safe RLock. Auto-creates DB at `~/.spiderfoot/spiderfoot.db`.
- **`SpiderFootCorrelator`** (`spiderfoot/correlation.py`) — Post-scan rule engine that processes YAML rules from `correlations/` against scan results.
- **`SpiderFootHelpers`** (`spiderfoot/helpers.py`) — Static utility class for type detection, module loading, path helpers, regex matching.

### Event-Driven Module System

Modules follow a pub/sub pattern:
1. Each module declares `watchedEvents()` (input) and `producedEvents()` (output).
2. `handleEvent(event)` processes incoming events and calls `self.notifyListeners(new_event)` to emit results.
3. Events chain via `sourceEvent`, creating a full discovery graph from target to findings.
4. Module template: `modules/sfp_template.py`. All modules are `modules/sfp_*.py`.

### Module Conventions

- `meta` dict: `name`, `summary`, `flags` (`apikey`, `slow`, `invasive`, `tool`), `useCases` (`Passive`, `Footprint`, `Investigate`), `categories`, `dataSource`.
- `opts` / `optdescs` dicts for user-configurable options. API keys use `api_key` in the name.
- `self.results = self.tempStorage()` in `setup()` to track processed data and avoid duplicates.
- `self.errorState` flag to stop processing on failure.
- `self.checkForStop()` in loops to respect user abort requests.
- Use `self.sf.fetchUrl()` for HTTP requests (inherits global timeout/proxy/UA settings).

### Data Flow

```
Target → SpiderFootScanner → ThreadPool → Modules (pub/sub events) → SpiderFootDb
                                                                        ↓
                                                              SpiderFootCorrelator
                                                              (YAML rules post-scan)
```

## Linting

Flake8 with max line length 120, max complexity 60, Google docstring convention. Config in `setup.cfg`. Key ignored rules: E501, W503, B006, Q000. Modules have relaxed rules (SIM102, SIM113, SIM114, E721 ignored).

## Testing

Tests are in `test/` with `unit/`, `integration/`, and `acceptance/` subdirectories. Uses pytest with xdist (parallel), coverage, and mock plugins. Test dependencies are in `test/requirements.txt` (separate from project dev deps). CI runs on Python 3.10-3.13 across Ubuntu and macOS.

## Docker

```bash
docker build -t spiderfoot .                     # Alpine 3.20 + Python 3.12
docker run -p 5001:5001 -v sf_data:/var/lib/spiderfoot spiderfoot
docker-compose up                                # Basic
docker-compose -f docker-compose.yml -f docker-compose-dev.yml up  # Dev (mounts code)
```
