# certik - HTTP(S) Certificate Manager (Terminal UI)

certik is an HTTP(S) certificate manager built in Rust with a terminal user interface (TUI) that runs over a HTTPS API server. It is a Turbo Vision application that allows you to load, inspect, verify, and export TLS certificate material from PEM/DER files, with a shared state API for server-side operations.

## Features

- **Certificate Operations**: Load leaf certificates, intermediate certificates, and private keys from PEM/DER files
- **Syntax Highlighted Display**: Certificate sets are rendered with color-coded fields (subject, issuer, dates, validity, path, etc.)
- **Chain Verification**: Validates certificate chains via signature checks, private key matching, and validity windows
- **API Server**: Runs a TLS server on port 24489 by default, serving certificate data via RESTful endpoints
- **TUI Interface**: Full terminal user interface for managing certificate sets with menus, windows, and keyboard navigation
- **Load Dialog Memory**: Remembers the last used directory for file dialogs, so you don't need to re-navigate
- **Horizontal Scrolling**: Horizontal scroll support for long certificate fields using KB_LEFT/RIGHT keys

## Installation

### Dependencies

Rust 1.76 or later is required. Install Rust from [rustup.rs](https://rustup.rs).

### Build from Source

```bash
cargo build
```

Run the application:

```bash
cargo run
```

### Running with No API Server

To run the TUI without starting the HTTPS API:

```bash
cargo run -- --no-api
```

### Usage Options

```
Usage: certik [OPTIONS]

Options:
  -V, --api-port <api-port>  HTTPS API server listen port (default: 24489)
  -H, --api-bind <api-bind>  HTTPS API bind address (default: 0.0.0.0)
  --tls-cert <tls-cert>      Path to TLS certificate PEM file
  --tls-key <tls-key>        Path to TLS private key PEM file
  --no-api                   Disable the HTTPS API server
  -h, --help                 Print help
  -V, --version              Print version
```

### Development Mode

By default, `--no-api` with automatic generation of ephemeral TLS credentials, use:

```bash
cargo run -- --no-api
```

To use custom TLS certificate/key, provide them with `--tls-cert` and `--tls-key`.

## Features

### TUI Interface

The TUI provides the following functionality:
- **File Menu**: New Certificate Set, Open Certificate/Intermediate/Key, Inspect File, About
- **Window Management**: Open/close certificate set windows, focus management
- **Keyboard Navigation**: Arrow keys, scrollbars, shortcuts
- **Status Line**: Shows current focus and program info

### Certificate Verification

certik performs comprehensive certificate verification:
- Checks signature chain from leaf to root
- Verifies private key matches leaf certificate
- Validates certificate validity windows (not_before, not_after)
- Reports PASS, PARTIAL PASS, or FAIL based on chain integrity and validity

### HTTP(S) API

The optional API server provides REST endpoints:
- `GET /certificate` - Returns leaf PEM (and text) from focused set
- `GET /certificate?format=text` - Returns leaf text
- `GET /intermediate` - Returns intermediates PEM (and text) from focused set
- `GET /intermediate?format=text` - Returns intermediates text
- `GET /key` - Returns private key PEM (and text) from focused set
- `GET /key?format=text` - Returns private key text

The API endpoints operate on the currently focused certificate set window.

## Architecture

### TUI Architecture (`src/app.rs`)

Custom main loop (not framework's `run`):
- Iterates `ui.app.running`, fetches events with `ui.app.get_event()`
- Dispatches via `ui.app.handle_event()`, then calls `ui.app.desktop.remove_closed_windows()`
- Calls `sync_scrollbars` and `sync_focus` after each event

### Shared State & Concurrency

`Arc<Mutex<CertSet>>` for the active set, `SharedLog`, and `SharedFocus`. The API runs concurrently on tokio.

### Custom Views

- `ServerLogView` - Renders the shared API log
- `CertSetView` - Renders certificate set with syntax highlighting, vertical scrollbar
- `SharedScrollBar` - Wrapper for native ScrollBar as frame child
- `WinKeyMarker` - Invisible marker tying a window to its `WinKey`

### File Dialog Memory

`Ui.last_directory` stores the last used directory per file dialog type (leaf, intermediate, key). After successful load, this is updated to the parent directory of the loaded file.

## License

AGPLv3