# AGENTS.md

Guidance for AI agents working in this repository.

## Project overview

`certik` is a Rust HTTP(S) certificate manager with two subsystems:

- A **TUI front-end** built on the `turbo-vision` framework.
- An **HTTPS management API** built on `tokio` + `hyper` 1.x + `rustls`.

## Crate layout

- `Cargo.toml` — single binary crate. Deps: `turbo-vision`, `tokio`, `hyper`,
  `hyper-util`, `http-body-util`, `bytes`, `tokio-rustls`, `rustls`,
  `rustls-pemfile`, `rustls-pki-types`, `rcgen`, `openssl`, `chrono`.
- `src/main.rs` — CLI arg parsing, wires up shared state, spawns the API task
  on a tokio runtime, then runs the TUI in the foreground.
- `src/app.rs` — the TUI (menu bar, status line, windows, custom views).
- `src/api.rs` — HTTPS API server (TLS acceptor + hyper service) and routing.
- `src/certs.rs` — PEM/DER decoding, report rendering, cert-set assembly and
  verification, plus export helpers.

## Shared state & concurrency

The TUI and the API server run concurrently and communicate through shared
`Arc`-wrapped state created in `main`:

- `SharedLog = Arc<Mutex<Vec<String>>>` — bounded API log (max 500 lines) shown
  by the TUI "API Server" window. Appended via `api::log_line`.
- `SharedSets = Arc<Mutex<Vec<Arc<Mutex<CertSet>>>>>` — every certificate set
  ever created. Sets are never removed, even when their window closes.
- `SharedFocus = Arc<AtomicUsize>` — id of the focused cert-set window. The API
  serves data only from the focused set; `api::NO_FOCUS` means none (API → 404).

The TUI updates `focus` each main-loop iteration (`sync_focus`). The tokio
runtime is kept alive until the TUI exits (`rt` is dropped after `app::run`).

## TUI architecture (`src/app.rs`)

The app runs a **custom main loop** (not the framework's `run`), replicating a
few framework behaviors:

- `main_loop` iterates `ui.app.running`, fetches events with
  `ui.app.get_event()`, dispatches via `ui.app.handle_event()`, then manually
  calls `ui.app.desktop.remove_closed_windows()` each iteration (the framework
  normally does this inside its own loop).
- After each event it calls `sync_scrollbars` and `sync_focus`.

### Window management & the `WinKeyMarker`

Every window the app creates is "managed": it gets a `WinKeyMarker` installed
as its **last** interior child by `add_managed_window`. `window_key` identifies
a window by probing its **last** child for the marker — never by downcasting
arbitrary children.

Why: the framework's `View::as_any` panics on views that don't override it
(framework views like `TextViewer`, `Background`, `ScrollBar`). certik's custom
views *do* override `as_any`. `window_key` wraps the probe in
`catch_unwind`/`AssertUnwindSafe` and a global panic hook silences the expected
`"as_any() not implemented"` message so it doesn't spam the terminal.

`WinKey` classifies windows: `Server`, `Set(usize)`, `Aux(u32)`.

### Custom views

Four custom views implement `turbo_vision::views::View`:

- `ServerLogView` — renders the shared API log, top-down scrolling.
- `CertSetView` — renders a certificate set from shared state with syntax
  coloring; owns a vertical `ScrollBar`.
- `SharedScrollBar` — a thin wrapper letting a native `ScrollBar` act as a
  Window **frame child** (the framework's own `EditWindow::SharedScrollBar` is
  private). It shares the `ScrollBar` via `Rc<RefCell<ScrollBar>>` with its
  `CertSetView`.
- `WinKeyMarker` — invisible/inert marker tying a window to its `WinKey`.

**View trait requirements** (important): each custom view must provide `core()`
and `core_mut()` returning a `ViewCore` (they store a `core` field), plus
`as_any`/`as_any_mut`. `draw`, `handle_event`, and `get_palette` are required;
`bounds`/`set_bounds`/`grow_mode`/`set_grow_mode`/`can_focus` are overridden as
needed.

### Border scrollbar wiring (frame children)

`Window::add_frame_child` / `update_frame_child` manage frame children. The
framework never sends events to frame children (only `frame` and `interior`),
so certik:

- routes mouse events over a scrollbar to it directly in the main loop
  (`route_scrollbar_mouse`) before the framework sees them;
- repositions each window's border scrollbar every frame in `sync_scrollbars`
  because `Window::set_bounds` does not move frame children on resize.

`CertSetView` pulls its scroll position from the shared `ScrollBar` at draw
time (the scrollbar is the source of truth, since mouse clicks change it
directly). Mouse wheel is handled in the view (the framework ScrollBar doesn't).

### Window maximize / minimize (shade)

`WinState.saved_bounds` holds the pre-shade bounds (`Some` = shaded). Window
menu actions (`Zoom`/`Minimize`/`Restore`) resolve the topmost window's key and
apply the effective action (zoom falls back to the framework's
`desktop.zoom_top_window()`; minimize shades to title+border via `set_bounds`).

### Menus & status line

Menus are built with `MenuBuilder` (`item`, `item_key`, `separator`, `build`);
submenus via `MenuBar::add_submenu(SubMenu::new(...))`. Status items use
`StatusItemBuilder`. Custom commands start at `CM_NEW_SET = 200` and go up
through `CM_ABOUT = 209` (reserved range above `CM_USER`). `CM_ABOUT` is defined
locally (the framework no longer ships one).

## API subsystem (`src/api.rs`)

- **Routing**: `route(method, path)` is a pure function for stateless routes
  (`/ping`). Stateful endpoints (`/certificate`, `/intermediate`, `/key`) are
  handled in `handle`, only for the focused set, with a `?format=` query param
  (`pem` default, or `text`).
- **TLS**: `build_acceptor` loads `--tls-cert`/`--tls-key` PEM files, or
  generates an ephemeral self-signed cert with `rcgen` in dev mode.
- **Server loop**: `run` binds a `TcpListener`, then `serve` accepts
  connections and spawns a tokio task per connection, wrapping each in
  `TlsAcceptor` before handing it to a hyper auto connection builder.
- `api::hex` is a small hex formatter reused elsewhere (e.g. `certs.rs`).

## Certificate handling (`src/certs.rs`)

- `analyze_file(path)` → human-readable text report for PEM (multi-section) and
  DER files (cert, private key, public key, CSR). Uses `openssl` for decoding.
- `extract_material(path, slot)` → pulls the material relevant to a
  `LoadSlot` (`Leaf` = first cert, `Intermediates` = all certs, `Key` = first
  private key).
- `CertSet` — a set under assembly: leaf cert, intermediates, private key, plus
  a `version` counter bumped on every mutation so `CertSetView` can re-render
  lazily (renders only when `version` changes).
- `verify_set(&set)` — builds the chain via signature checks, verifies the
  private key matches the leaf, checks validity windows, and reports an overall
  PASS / PARTIAL PASS / FAIL. Uses `chrono` for day-count math.
- Export helpers for the API: `leaf_pem`, `leaf_text`, `intermediates_pem`,
  `intermediates_text`, `key_pem`, `key_text`.

## Testing

`cargo test` runs unit tests in `api`, `certs`, and end-to-end TLS tests
(real `TlsAcceptor` + hyper over a socket, self-signed certs generated with
`rcgen`). Tests write scratch files under the system temp dir and clean up
after themselves. A chain fixture helper (`ca_chain_materials`) builds a
root → intermediate → leaf chain with `rcgen` for chain-verification tests.

## Useful commands

- `cargo build` / `cargo run`
- `cargo test`
- `cargo run -- --no-api` — run the TUI without starting the HTTPS API.
- `cargo run -- --help` — full CLI options (`--api-bind`, `--api-port`,
  `--tls-cert`, `--tls-key`, `--cert`, `--key`, `--no-api`).