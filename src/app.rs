//! TUI front-end built on the turbo-vision framework (v1.3.1).
//!
//! Layout:
//!   - Top menu bar: File / Edit / Help
//!   - Status line with shortcut hints
//!   - "API Server" window: live view of the API subsystem log
//!   - Certificate Set windows (File > New): each shows leaf certificate,
//!     intermediate certificates and private key; components are loaded into
//!     the active window via File > Open Certificate / Intermediate / Key.
//!     Once a set is complete its chain/key/validity is verified automatically.

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::Mutex;

use turbo_vision::app::Application;
use turbo_vision::core::command::{CommandId, CM_ABOUT, CM_CASCADE, CM_COPY, CM_CUT, CM_PASTE, CM_QUIT, CM_REDO, CM_TILE, CM_UNDO};
use turbo_vision::core::draw::DrawBuffer;
use turbo_vision::core::error::Result;
use turbo_vision::core::event::{Event, EventType, KB_ALT_X, KB_DOWN, KB_F10, KB_F3, KB_UP};
use turbo_vision::core::geometry::Rect;
use turbo_vision::core::menu_data::{Menu, MenuItem};
use turbo_vision::core::palette::{Attr, TvColor, colors, Palette};
use turbo_vision::core::state::{GF_GROW_HI_X, GF_GROW_HI_Y, GrowFlags};
use turbo_vision::helpers::msgbox::{message_box, MF_ERROR, MF_INFORMATION, MF_OK_BUTTON};
use turbo_vision::terminal::Terminal;
use turbo_vision::views::file_dialog::FileDialog;
use turbo_vision::views::menu_bar::{MenuBar, SubMenu};
use turbo_vision::views::status_line::{StatusItem, StatusLine};
use turbo_vision::views::scrollbar::ScrollBar;
use turbo_vision::views::text_viewer::TextViewerBuilder;
use turbo_vision::views::view::{write_line_to_terminal, View};
use turbo_vision::views::window::{Window, WindowBuilder};

use crate::api::SharedLog;
use crate::api;
use crate::certs::{CertSet, LoadSlot};

/// Custom commands start above the framework's reserved range.
const CM_NEW_SET: CommandId = 200; // File > New Certificate Set
const CM_LOAD_CERT: CommandId = 201; // File > Open Certificate...
const CM_LOAD_INT: CommandId = 202; // File > Open Intermediate...
const CM_LOAD_KEY: CommandId = 203; // File > Open Key...
const CM_SHORTCUTS: CommandId = 204;
const CM_INSPECT: CommandId = 205; // File > Inspect File...
const CM_WIN_ZOOM: CommandId = 206; // Window > Zoom (maximize/restore)
const CM_WIN_MINIMIZE: CommandId = 207; // Window > Minimize (shade)
const CM_WIN_RESTORE: CommandId = 208; // Window > Restore

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Identifies a managed window (for minimize/zoom state and title buttons).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum WinKey {
    Server,
    Set(usize), // CertSet id
    Aux(u32),   // transient text/report windows
}

impl WinKey {
    fn next_aux() -> Self {
        static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
        WinKey::Aux(COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }
}

#[derive(Debug, Clone, Copy)]
enum WinAction {
    Zoom,
    Minimize,
    Restore,
}

/// Per-window UI state: `saved_bounds` is `Some` while shaded (minimized).
#[derive(Default)]
struct WinState {
    saved_bounds: Option<Rect>,
}

struct Ui {
    app: Application,
    /// All sets ever created (windows can be closed, sets stay).
    /// Shared with the API server for serving certificate data.
    sets: api::SharedSets,
    /// Id of the focused certificate-set window, shared with the API server so
    /// it serves data only from the focused set. Updated each loop iteration.
    focus: api::SharedFocus,
    /// Shared API/server log shown by the API Server window.
    log: SharedLog,
    /// Shade/minimize state per managed window (Window > Minimize / Restore).
    win_state: HashMap<WinKey, WinState>,
    /// Frame-child index of the native border scrollbar per window (only
    /// windows that own a scrollbar are present).
    scrollbar_indices: HashMap<WinKey, usize>,
    /// Shared handle to each certificate-set window's vertical scrollbar, so
    /// the main loop can route mouse clicks/drags on the border scrollbar to
    /// it (frame children do not receive events from the framework).
    scrollbars: HashMap<WinKey, Rc<RefCell<ScrollBar>>>,
}

pub fn run(log: SharedLog, sets: api::SharedSets, focus: api::SharedFocus, load_certs: &[PathBuf], load_keys: &[PathBuf]) -> Result<()> {
    // The framework's `View::as_any()` panics on views that don't override it
    // (TextViewer, Background, ScrollBar, etc.). certik's `window_key` probes
    // a window's last child for its own `WinKeyMarker` (the only view that
    // overrides `as_any`); unmanaged windows (e.g. the welcome window) have a
    // framework view there, which trips the default panic hook every frame.
    // We catch those expected panics with `catch_unwind` and silence this
    // specific message so they don't spam the terminal.
    std::panic::set_hook(Box::new(|info| {
        let msg = info.to_string();
        if msg.contains("as_any() not implemented") {
            return; // expected: certik probes for its own marker; not an error
        }
        eprintln!("{msg}");
    }));

    let mut app = Application::new()?;
    let (w, h) = app.terminal.size();

    build_menu_bar(&mut app, w);
    build_status_line(&mut app, w, h);

    let mut ui = Ui {
        app,
        sets,
        focus,
        log: log.clone(),
        win_state: HashMap::new(),
        scrollbar_indices: HashMap::new(),
        scrollbars: HashMap::new(),
    };

    // API server status window (live view onto the shared log).
    let sw_w = 58.min(w - 4).max(24);
    let sw_h = 11.min(h - 3).max(6);
    add_server_window(&mut ui, Rect::new(2, 1, 2 + sw_w, 1 + sw_h));

    // Welcome window (added directly, not managed: it is purely informational
    // and does not participate in minimize/zoom/tile bookkeeping).
    let welcome = format!(
        "certik v{}\n\n\
         HTTP(S) certificate handler / storage / manager / controller / deployer.\n\n\
         File > New Certificate Set      opens a set window\n\
         File > Open Certificate...  F3  load leaf into active set\n\
         File > Open Intermediate...     load chain cert(s)\n\
         File > Open Key...              load private key\n\n\
         When certificate + key are loaded, the set is verified:\n\
         chain signatures, key match and validity.\n\n\
         The HTTPS API serves GET /ping -> pong; see the API Server\n\
         window for requests arriving at the endpoint.",
        env!("CARGO_PKG_VERSION")
    );
    let (ww, wh) = ui.app.terminal.size();
    let win_w = (ww - 8).max(30);
    let win_h = (wh - 6).max(8);
    let x = (ww - win_w) / 2;
    let y = (wh - win_h) / 2;
    let mut welcome_window = WindowBuilder::new()
        .bounds(Rect::new(x, y, x + win_w, y + win_h))
        .title("Welcome")
        .build();
    let mut welcome_viewer = TextViewerBuilder::new()
        .bounds(Rect::new(0, 0, win_w - 2, win_h - 2))
        .build();
    welcome_viewer.set_text(&welcome);
    welcome_window.add(Box::new(welcome_viewer));
    ui.app.desktop.add(Box::new(welcome_window));

    // Pre-load files from CLI flags (--cert, --key).
    if !load_certs.is_empty() || !load_keys.is_empty() {
        new_certificate_set(&mut ui);
        let set = {
            let sets = ui.sets.lock().expect("sets lock");
            sets.last().cloned().expect("just created set")
        };
        let mut loaded_any = false;
        for path in load_certs {
            match crate::certs::extract_material(path, crate::certs::LoadSlot::Leaf) {
                Ok(crate::certs::ExtractedMaterial::Certificate(cert)) => {
                    set.lock().expect("set lock").load_leaf(path, cert);
                    loaded_any = true;
                }
                Ok(_) => {}
                Err(e) => {
                    crate::api::log_line(&ui.log, format!("failed to load cert {path:?}: {e}"));
                }
            }
        }
        for path in load_keys {
            match crate::certs::extract_material(path, crate::certs::LoadSlot::Key) {
                Ok(crate::certs::ExtractedMaterial::PrivateKey(key)) => {
                    set.lock().expect("set lock").load_key(path, key);
                    loaded_any = true;
                }
                Ok(_) => {}
                Err(e) => {
                    crate::api::log_line(&ui.log, format!("failed to load key {path:?}: {e}"));
                }
            }
        }
        if loaded_any {
            let mut s = set.lock().expect("set lock");
            if s.is_complete() && s.verification.is_none() {
                if let Ok(report) = crate::certs::verify_set(&s) {
                    let failed = report.contains("FAIL");
                    let overall = report
                        .lines()
                        .find(|l| l.starts_with("Overall"))
                        .unwrap_or("")
                        .trim_start_matches("Overall    : ")
                        .to_string();
                    crate::api::log_line(
                        &ui.log,
                        format!("verification: {overall}"),
                    );
                    s.verification = Some(report);
                    let _ = failed;
                }
            }
        }
    }

    main_loop(&mut ui);
    ui.app.terminal.shutdown()?;
    Ok(())
}

fn main_loop(ui: &mut Ui) {
    while ui.app.running {
        if let Some(mut event) = ui.app.get_event() {
            // Frame children (border scrollbars) do not receive events from
            // the framework's Window/Group dispatch, so route mouse events
            // over a scrollbar to it before the framework handles the event.
            route_scrollbar_mouse(ui, &mut event);

            ui.app.handle_event(&mut event);

            if event.what == EventType::Command {
                match event.command {
                    CM_NEW_SET => new_certificate_set(ui),
                    CM_LOAD_CERT => load_component(ui, LoadSlot::Leaf),
                    CM_LOAD_INT => load_component(ui, LoadSlot::Intermediates),
                    CM_LOAD_KEY => load_component(ui, LoadSlot::Key),
                    CM_INSPECT => inspect_file(ui),
                    CM_WIN_ZOOM => window_menu_action(ui, WinAction::Zoom),
                    CM_WIN_MINIMIZE => window_menu_action(ui, WinAction::Minimize),
                    CM_WIN_RESTORE => window_menu_action(ui, WinAction::Restore),
                    CM_SHORTCUTS => show_shortcuts(ui),
                    CM_ABOUT => show_about(ui),
                    _ => {}
                }
            }

            // The framework's `run()` loop removes SF_CLOSED windows each
            // iteration; certik runs its own loop, so replicate that sweep
            // here so the frame close button actually closes windows.
            ui.app.desktop.remove_closed_windows();
        }

        sync_scrollbars(ui);
        sync_focus(ui);
    }
}

/// Route mouse events that land on a border scrollbar to that scrollbar.
///
/// Border scrollbars are installed as `Window` frame children, which the
/// framework never sends events to (only `frame` and `interior` receive
/// events). A mouse click on the scrollbar would otherwise fall through and
/// be dropped. Here we forward MouseDown/MouseMove/MouseUp over a scrollbar to
/// the scrollbar itself (which handles arrow clicks, page jumps, and thumb
/// drags), then clear the event so the framework doesn't double-process it.
fn route_scrollbar_mouse(ui: &mut Ui, event: &mut Event) {
    if !matches!(
        event.what,
        EventType::MouseDown | EventType::MouseMove | EventType::MouseUp
    ) {
        return;
    }

    let pos = event.mouse.pos;

    // Search topmost-first so the scrollbar of the front window wins.
    let d = &ui.app.desktop;
    for i in (0..d.child_count()).rev() {
        let Some(win) = d.child_at(i).as_any().downcast_ref::<Window>() else {
            continue;
        };
        let Some(key) = window_key(win) else { continue };
        let Some(sb) = ui.scrollbars.get(&key) else { continue };

        // Scrollbar bounds are absolute (frame child). Check containment.
        if sb.borrow().bounds().contains(pos) {
            sb.borrow_mut().handle_event(event);
            // If the scrollbar consumed it (cleared), stop here.
            if event.what == EventType::Nothing {
                return;
            }
        }
    }
}

/// Reposition every window's native border scrollbar onto its current right
/// edge. The framework does not move `frame_children` when a `Window` resizes
/// (see `Window::set_bounds`), so like the framework's `EditWindow` we
/// recalculate positions as needed — here, each frame during the main loop
/// so scrollbars never lag the border during drag-resize.
fn sync_scrollbars(ui: &mut Ui) {
    for i in 0..ui.app.desktop.child_count() {
        let Some(win) = ui.app.desktop.child_at(i).as_any().downcast_ref::<Window>() else {
            continue;
        };
        let Some(key) = window_key(win) else { continue };
        let Some(&sb_idx) = ui.scrollbar_indices.get(&key) else {
            continue;
        };
        // Window frame absolute coords; the vertical scrollbar hugs the right
        // border, spanning the title rows' contents (skip title + bottom).
        // Skip windows too short/small to host a scrollbar column.
        let b = win.bounds();
        if b.b.y - 2 > b.a.y + 1 && b.b.x > b.a.x + 1 {
            let col = Rect::new(b.b.x - 1, b.a.y + 1, b.b.x, b.b.y - 2);
            if let Some(v) = ui.app.desktop.window_at_mut(i) {
                if let Some(win) = v.as_any_mut().downcast_mut::<Window>() {
                    win.update_frame_child(sb_idx, col);
                }
            }
        }
    }
}

/// Publish the id of the currently focused certificate-set window to the
/// shared `focus` value so the API server serves data from the focused set.
/// If no certificate-set window is focused, the API serves nothing (404).
fn sync_focus(ui: &mut Ui) {
    let id = active_set(ui).map(|s| s.lock().map(|st| st.id).unwrap_or(api::NO_FOCUS)).unwrap_or(api::NO_FOCUS);
    ui.focus.store(id, std::sync::atomic::Ordering::SeqCst);
}

// ---------------------------------------------------------------------------
// Title-bar button interception
// ---------------------------------------------------------------------------

/// Map a raw button action to its effective operation given current state.
fn effective_action(ui: &Ui, key: WinKey, action: WinAction) -> WinAction {
    let minimized = ui
        .win_state
        .get(&key)
        .is_some_and(|s| s.saved_bounds.is_some());
    match action {
        WinAction::Zoom | WinAction::Minimize if minimized => WinAction::Restore,
        WinAction::Zoom => WinAction::Zoom,
        WinAction::Minimize => WinAction::Minimize,
        WinAction::Restore => WinAction::Restore,
    }
}

// ---------------------------------------------------------------------------
// Menus and status line
// ---------------------------------------------------------------------------

fn build_menu_bar(app: &mut Application, w: i16) {
    let mut menu_bar = MenuBar::new(Rect::new(0, 0, w, 1));

    menu_bar.add_submenu(SubMenu::new(
        "~F~ile",
        Menu::from_items(vec![
            MenuItem::with_shortcut("~N~ew Certificate Set", CM_NEW_SET, 0, "", 0),
            MenuItem::separator(),
            MenuItem::with_shortcut("~O~pen Certificate...", CM_LOAD_CERT, KB_F3, "F3", 0),
            MenuItem::with_shortcut("Open ~I~ntermediate...", CM_LOAD_INT, 0, "", 0),
            MenuItem::with_shortcut("Open ~K~ey...", CM_LOAD_KEY, 0, "", 0),
            MenuItem::with_shortcut("~I~nspect File...", CM_INSPECT, 0, "", 0),
            MenuItem::separator(),
            MenuItem::with_shortcut("E~x~it", CM_QUIT, KB_ALT_X, "Alt+X", 0),
        ]),
    ));

    menu_bar.add_submenu(SubMenu::new(
        "~E~dit",
        Menu::from_items(vec![
            MenuItem::new("~U~ndo", CM_UNDO, 0, 0),
            MenuItem::new("~R~edo", CM_REDO, 0, 0),
            MenuItem::separator(),
            MenuItem::new("Cu~t~", CM_CUT, 0, 0),
            MenuItem::new("~C~opy", CM_COPY, 0, 0),
            MenuItem::new("~P~aste", CM_PASTE, 0, 0),
        ]),
    ));

    menu_bar.add_submenu(SubMenu::new(
        "~W~indow",
        Menu::from_items(vec![
            MenuItem::with_shortcut("~T~ile", CM_TILE, 0, "", 0),
            MenuItem::with_shortcut("C~a~scade", CM_CASCADE, 0, "", 0),
            MenuItem::separator(),
            MenuItem::new("~Z~oom / Restore", CM_WIN_ZOOM, 0, 0),
            MenuItem::new("Mi~n~imize", CM_WIN_MINIMIZE, 0, 0),
            MenuItem::new("~R~estore", CM_WIN_RESTORE, 0, 0),
        ]),
    ));

    menu_bar.add_submenu(SubMenu::new(
        "~H~elp",
        Menu::from_items(vec![
            MenuItem::with_shortcut("~K~eyboard Shortcuts", CM_SHORTCUTS, 0, "", 0),
            MenuItem::separator(),
            MenuItem::with_shortcut("~A~bout...", CM_ABOUT, 0, "", 0),
        ]),
    ));

    app.set_menu_bar(menu_bar);
}

fn build_status_line(app: &mut Application, w: i16, h: i16) {
    app.set_status_line(StatusLine::new(
        Rect::new(0, h - 1, w, h),
        vec![
            StatusItem::new("~F3~ Open Cert", KB_F3, CM_LOAD_CERT),
            StatusItem::new("~F10~ Menu", KB_F10, 0),
            StatusItem::new("~Alt+X~ Exit", KB_ALT_X, CM_QUIT),
        ],
    ));
}

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------

/// Install a managed window, tagging it with a `WinKeyMarker`.
///
/// Every window created by the app is managed, so windows are always
/// identifiable by probing their last child (the marker) - never by
/// downcasting arbitrary children (framework views panic on `as_any`).
fn add_managed_window(
    ui: &mut Ui,
    mut window: Window,
    key: WinKey,
) {
    // Marker is the last interior child so existing child indices (e.g. the
    // border scrollbar recorded earlier in `new_certificate_set`) stay stable.
    window.add(Box::new(WinKeyMarker { key }));
    ui.win_state.entry(key).or_default();
    ui.app.desktop.add(Box::new(window));
}

fn add_server_window(ui: &mut Ui, bounds: Rect) {
    let log = ui.log.clone();
    let mut window = Window::new(bounds, "API Server");
    let interior = Rect::new(0, 0, bounds.width() - 2, bounds.height() - 2);
    window.add(Box::new(ServerLogView::new(interior, log)));
    add_managed_window(ui, window, WinKey::Server);
}

fn open_text_window(ui: &mut Ui, title: &str, text: &str, cascade: i16) {
    let (w, h) = ui.app.terminal.size();
    let win_w = (w - 8).max(30);
    let win_h = (h - 6).max(8);
    let x = ((w - win_w) / 2 + cascade * 2).clamp(0, (w - win_w).max(0));
    let y = ((h - win_h) / 2 + cascade * 2).clamp(0, (h - win_h - 1).max(0));

    let mut window = WindowBuilder::new()
        .bounds(Rect::new(x, y, x + win_w, y + win_h))
        .title(title)
        .build();

    let mut viewer = TextViewerBuilder::new()
        .bounds(Rect::new(0, 0, win_w - 2, win_h - 2))
        .build();
    viewer.set_text(text);
    window.add(Box::new(viewer));
    add_managed_window(ui, window, WinKey::next_aux());
}

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

/// Create a fresh certificate set and open its window (becomes active).
fn new_certificate_set(ui: &mut Ui) {
    let id = {
        let sets = ui.sets.lock().expect("sets lock");
        sets.len() + 1
    };
    let set = Arc::new(Mutex::new(CertSet::new(id)));
    {
        let mut sets = ui.sets.lock().expect("sets lock");
        sets.push(Arc::clone(&set));
    }

    let (w, h) = ui.app.terminal.size();
    let win_w = (w - 10).max(40);
    let win_h = (h - 8).max(12);
    let x = ((w - win_w) / 2 + id as i16 * 3).clamp(0, (w - win_w).max(0));
    let y = ((h - win_h) / 2 + id as i16 * 2).clamp(0, (h - win_h - 1).max(0));

    let title = {
        let s = set.lock().expect("set lock");
        s.title.clone()
    };
    let mut window = Window::new(Rect::new(x, y, x + win_w, y + win_h), &title);
    let interior = Rect::new(0, 0, win_w - 2, win_h - 2);

    // Native border scrollbar: installed as a Window frame child (window-
    // relative coords on the right border) and shared with the view.
    let sb = Rc::new(RefCell::new(ScrollBar::new_vertical(Rect::new(
        win_w - 1,
        1,
        win_w,
        win_h - 2,
    ))));
    window.add(Box::new(CertSetView::new(interior, Arc::clone(&set), Rc::clone(&sb))));
    let sb_idx = window.add_frame_child(Box::new(SharedScrollBar(Rc::clone(&sb))));
    let key = WinKey::Set(id);
    ui.scrollbar_indices.insert(key, sb_idx);
    ui.scrollbars.insert(key, sb);
    add_managed_window(ui, window, key);
}

/// Classify a window by probing its LAST child, which is always the certik
/// `WinKeyMarker` installed by `add_managed_window`.
///
/// Only `WinKeyMarker` (and certik's other custom views) override `as_any`;
/// framework views such as `TextViewer` panic on `as_any`. Unmanaged windows
/// (e.g. the welcome window) have no marker, so their last child is a plain
/// framework view. We therefore probe defensively: a window whose last child
/// is not a `WinKeyMarker` simply yields `None` instead of crashing the app.
fn window_key(win: &Window) -> Option<WinKey> {
    let last = win.child_count().checked_sub(1)?;
    let child = win.child_at(last);
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        child.as_any().downcast_ref::<WinKeyMarker>().map(|m| m.key)
    }))
    .ok()
    .flatten()
}

/// Resolve the currently active certificate set: topmost CertSetView in the
/// desktop z-order (later children are on top; index 0 is the background).
fn active_set(ui: &Ui) -> Option<Arc<Mutex<CertSet>>> {
    let d = &ui.app.desktop;
    for i in (0..d.child_count()).rev() {
        let view = d.child_at(i);
        let Some(win) = view.as_any().downcast_ref::<Window>() else {
            continue;
        };
        if let Some(WinKey::Set(id)) = window_key(win) {
            let sets = ui.sets.lock().expect("sets lock");
            return sets
                .iter()
                .find(|s: &&Arc<Mutex<CertSet>>| matches!(s.lock(), Ok(st) if st.id == id))
                .cloned();
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Window maximize / minimize (shade)
// ---------------------------------------------------------------------------

/// Find the desktop index of the window with the given key.
fn find_window_index(ui: &Ui, key: WinKey) -> Option<usize> {
    let d = &ui.app.desktop;
    for i in 0..d.child_count() {
        let view = d.child_at(i);
        if let Some(win) = view.as_any().downcast_ref::<Window>() {
            if window_key(win) == Some(key) {
                return Some(i);
            }
        }
    }
    None
}

/// Handle a Window-menu action, targeting the active (topmost) window.
fn window_menu_action(ui: &mut Ui, action: WinAction) {
    let key = {
        let d = &ui.app.desktop;
        let Some(top) = d.child_count().checked_sub(1) else {
            return;
        };
        match d
            .child_at(top)
            .as_any()
            .downcast_ref::<Window>()
            .and_then(window_key)
        {
            Some(k) => k,
            None => return,
        }
    };
    let effective = effective_action(ui, key, action);
    apply_window_action(ui, key, effective);
}

fn apply_window_action(ui: &mut Ui, key: WinKey, action: WinAction) {
    let Some(index) = find_window_index(ui, key) else {
        return;
    };

    match action {
        WinAction::Zoom => {
            // Native maximize/restore: the framework zooms the topmost window
            // to the desktop extent and toggles back to its own saved bounds.
            ui.app.desktop.zoom_top_window();
        }
        WinAction::Minimize => {
            let bounds = {
                let d = &ui.app.desktop;
                match d.child_at(index).as_any().downcast_ref::<Window>() {
                    Some(w) => w.bounds(),
                    None => return,
                }
            };
            // Shade down to just the title bar + bottom border.
            let shaded = Rect::new(bounds.a.x, bounds.a.y, bounds.b.x, bounds.a.y + 2);
            ui.win_state.insert(key, WinState { saved_bounds: Some(bounds) });
            if let Some(win_view) = ui.app.desktop.window_at_mut(index) {
                win_view.set_bounds(shaded);
            }
        }
        WinAction::Restore => {
            let saved = ui
                .win_state
                .get_mut(&key)
                .and_then(|s| s.saved_bounds.take());
            if let Some(saved) = saved {
                if let Some(win_view) = ui.app.desktop.window_at_mut(index) {
                    win_view.set_bounds(saved);
                }
            }
        }
    }
}

fn load_component(ui: &mut Ui, slot: LoadSlot) {
    let Some(set) = active_set(ui) else {
        message_box(
            &mut ui.app,
            "No certificate set window.\n\nUse File > New Certificate Set first.",
            MF_INFORMATION | MF_OK_BUTTON,
        );
        return;
    };

    let dialog_title = match slot {
        LoadSlot::Leaf => "Open Certificate (leaf)",
        LoadSlot::Intermediates => "Open Intermediate Certificate(s)",
        LoadSlot::Key => "Open Private Key",
    };

    let path = match run_file_dialog(&mut ui.app, dialog_title) {
        Some(p) => p,
        None => return, // canceled
    };

    match crate::certs::extract_material(&path, slot) {
        Ok(material) => {
            {
                let mut s = set.lock().expect("set lock");
                match material {
                    crate::certs::ExtractedMaterial::Certificate(cert) => s.load_leaf(&path, cert),
                    crate::certs::ExtractedMaterial::Certificates(certs) => {
                        s.load_intermediates(&path, certs)
                    }
                    crate::certs::ExtractedMaterial::PrivateKey(key) => s.load_key(&path, key),
                }
            }

            crate::api::log_line(
                &ui.log,
                format!(
                    "loaded {} into {} from {}",
                    slot_name(slot),
                    set.lock().expect("set lock").title,
                    path.display()
                ),
            );

            // Everything loaded? Try to verify now.
            let mut verify_note: Option<(bool, String)> = None;
            {
                let mut s = set.lock().expect("set lock");
                if s.is_complete() && s.verification.is_none() {
                    match crate::certs::verify_set(&s) {
                        Ok(report) => {
                            let failed = report.contains("FAIL");
                            let overall = report
                                .lines()
                                .find(|l| l.starts_with("Overall"))
                                .unwrap_or("")
                                .trim_start_matches("Overall    : ")
                                .to_string();
                            verify_note = Some((!failed, overall));
                            s.verification = Some(report);
                        }
                        Err(e) => {
                            s.verification = Some(format!("verification error: {e}"));
                            verify_note = Some((false, format!("verification error: {e}")));
                        }
                    }
                }
            }

            if let Some((ok, summary)) = verify_note {
                message_box(
                    &mut ui.app,
                    &format!(
                        "\x03Verification {}\n\n{summary}",
                        if ok { "completed" } else { "FAILED" }
                    ),
                    if ok {
                        MF_INFORMATION | MF_OK_BUTTON
                    } else {
                        MF_ERROR | MF_OK_BUTTON
                    },
                );
            }
        }
        Err(e) => {
            message_box(
                &mut ui.app,
                &format!("Could not load file:\n{e}"),
                MF_ERROR | MF_OK_BUTTON,
            );
        }
    }
}

fn slot_name(slot: LoadSlot) -> &'static str {
    match slot {
        LoadSlot::Leaf => "certificate",
        LoadSlot::Intermediates => "intermediate(s)",
        LoadSlot::Key => "private key",
    }
}

/// Analyze any certificate-ish file and show the report in a window.
fn inspect_file(ui: &mut Ui) {
    let Some(path) = run_file_dialog(&mut ui.app, "Inspect File") else {
        return;
    };
    match crate::certs::analyze_file(&path) {
        Ok(report) => {
            crate::api::log_line(&ui.log, format!("inspected {}", path.display()));
            open_text_window(ui, "File Report", &report, 1);
        }
        Err(e) => {
            message_box(
                &mut ui.app,
                &format!("Could not analyze file:\n{e}"),
                MF_ERROR | MF_OK_BUTTON,
            );
        }
    }
}

fn run_file_dialog(app: &mut Application, title: &str) -> Option<PathBuf> {
    let (w, h) = app.terminal.size();
    let dlg_w = 62.min(w - 4).max(30);
    let dlg_h = 20.min(h - 4).max(12);
    let dx = (w - dlg_w) / 2;
    let dy = (h - dlg_h) / 2;

    let mut dialog = FileDialog::new(
        Rect::new(dx, dy, dx + dlg_w, dy + dlg_h),
        title,
        "*", // all files; type a pattern like "*.pem" to filter
        None,
    )
    .build();

    dialog.execute(app)
}

fn show_about(ui: &mut Ui) {
    message_box(
        &mut ui.app,
        "\x03Certik\n\x03 \nVersion 0.1.0\nHTTP(S) certificate manager.\n \x03TUI: turbo-vision | API: hyper + rustls",
        MF_INFORMATION | MF_OK_BUTTON,
    );
}

fn show_shortcuts(ui: &mut Ui) {
    message_box(
        &mut ui.app,
        "F3      Open certificate into active set\nAlt+X   Exit\nArrows/Wheel  Scroll windows",
        MF_INFORMATION | MF_OK_BUTTON,
    );
}

// ---------------------------------------------------------------------------
// ServerLogView - renders the shared API log directly from shared state
// ---------------------------------------------------------------------------

struct ServerLogView {
    bounds: Rect,
    log: SharedLog,
    /// Index of the first visible line (normal top-down scrolling).
    offset: usize,
    grow_mode: GrowFlags,
}

impl ServerLogView {
    fn new(bounds: Rect, log: Arc<Mutex<Vec<String>>>) -> Self {
        Self { bounds, log, offset: 0, grow_mode: GF_GROW_HI_X | GF_GROW_HI_Y }
    }
}

impl View for ServerLogView {
    fn bounds(&self) -> Rect {
        self.bounds
    }

    fn set_bounds(&mut self, bounds: Rect) {
        self.bounds = bounds;
    }

    fn draw(&mut self, terminal: &mut Terminal) {
        let width = self.bounds.width_clamped() as usize;
        let height = self.bounds.height_clamped() as usize;

        // Background.
        for y in 0..height {
            let blank = " ".repeat(width);
            let mut buf = DrawBuffer::new(width);
            buf.move_str(0, &blank, colors::NORMAL);
            write_line_to_terminal(terminal, self.bounds.a.x, self.bounds.a.y + y as i16, &buf);
        }

        if width == 0 || height == 0 {
            return;
        }

        // Snapshot the log (small, bounded buffer) so we can mutate self below.
        let lines: Vec<String> = match self.log.lock() {
            Ok(g) => g.clone(),
            Err(_) => return,
        };

        let total = lines.len();
        if total == 0 {
            let hint = "(no API activity yet)";
            let mut buf = DrawBuffer::new(width);
            buf.move_str(0, hint, colors::NORMAL);
            write_line_to_terminal(terminal, self.bounds.a.x, self.bounds.a.y, &buf);
            return;
        }

        let max_offset = total.saturating_sub(height);
        if self.offset > max_offset {
            self.offset = max_offset;
        }
        let start = self.offset;
        let end = (start + height).min(total);

        for (row, line) in lines[start..end].iter().enumerate() {
            draw_text_line(terminal, self.bounds, row, line, width);
        }
    }

    fn handle_event(&mut self, event: &mut Event) {
        scroll_handler(event, &mut self.offset);
    }

    fn can_focus(&self) -> bool {
        true
    }

    fn get_palette(&self) -> Option<Palette> {
        None
    }

    fn grow_mode(&self) -> GrowFlags {
        self.grow_mode
    }

    fn set_grow_mode(&mut self, grow_mode: GrowFlags) {
        self.grow_mode = grow_mode;
    }
}

// ---------------------------------------------------------------------------
// WinKeyMarker - ties a managed Window to its WinKey without probing into
// framework children (whose `as_any` panics). Installed as the last interior
// child by `add_managed_window`; it draws nothing and handles no events, so it
// is invisible and inert to the user.
// ---------------------------------------------------------------------------

struct WinKeyMarker {
    key: WinKey,
}

impl View for WinKeyMarker {
    fn bounds(&self) -> Rect {
        Rect::new(0, 0, 1, 1)
    }

    fn set_bounds(&mut self, _bounds: Rect) {}

    fn draw(&mut self, _terminal: &mut Terminal) {}

    fn handle_event(&mut self, _event: &mut Event) {}

    fn get_palette(&self) -> Option<Palette> {
        None
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

// ---------------------------------------------------------------------------
// SharedScrollBar - lets a native ScrollBar act as a Window frame child
// (mirrors the framework's EditWindow::SharedScrollBar, which certik cannot
// reach because it is private). The ScrollBar is shared with its CertSetView
// so the view can update value/total while the window owns the border slot.
// ---------------------------------------------------------------------------

struct SharedScrollBar(Rc<RefCell<ScrollBar>>);

impl View for SharedScrollBar {
    fn bounds(&self) -> Rect {
        self.0.borrow().bounds()
    }

    fn set_bounds(&mut self, bounds: Rect) {
        self.0.borrow_mut().set_bounds(bounds);
    }

    fn draw(&mut self, terminal: &mut Terminal) {
        self.0.borrow_mut().draw(terminal);
    }

    fn handle_event(&mut self, event: &mut Event) {
        self.0.borrow_mut().handle_event(event);
    }

    fn get_palette(&self) -> Option<Palette> {
        self.0.borrow().get_palette()
    }

    fn set_palette_chain(&mut self, node: Option<turbo_vision::core::palette_chain::PaletteChainNode>) {
        self.0.borrow_mut().set_palette_chain(node);
    }

    fn get_palette_chain(&self) -> Option<&turbo_vision::core::palette_chain::PaletteChainNode> {
        None
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

// ---------------------------------------------------------------------------
// CertSetView - renders a certificate set from shared state
// ---------------------------------------------------------------------------

struct CertSetView {
    bounds: Rect,
    set: Arc<Mutex<CertSet>>,
    offset: usize,
    seen_version: u64,
    cached_lines: Vec<String>,
    v_scrollbar: Rc<RefCell<ScrollBar>>,
    grow_mode: GrowFlags,
}

impl CertSetView {
    fn new(bounds: Rect, set: Arc<Mutex<CertSet>>, v_scrollbar: Rc<RefCell<ScrollBar>>) -> Self {
        Self {
            bounds,
            set,
            offset: 0,
            seen_version: u64::MAX,
            cached_lines: Vec::new(),
            v_scrollbar,
            grow_mode: GF_GROW_HI_X | GF_GROW_HI_Y,
        }
    }

    fn refresh_if_needed(&mut self) {
        let version = self.set.lock().map(|s| s.version).unwrap_or(self.seen_version);
        if version != self.seen_version || self.cached_lines.is_empty() {
            if let Ok(s) = self.set.lock() {
                self.cached_lines = s.render();
                self.seen_version = s.version;
                let max_off = self.cached_lines.len().saturating_sub(1);
                if self.offset > max_off {
                    self.offset = max_off;
                }
            }
        }
    }

    fn sync_scrollbar(&mut self) {
        let total = self.cached_lines.len() as i32;
        let height = self.bounds.height_clamped() as i32;
        let mut sb = self.v_scrollbar.borrow_mut();
        sb.set_total(total);
        // Arrow step = 1 line; page step = one viewport height.
        sb.set_params(self.offset as i32, 0, (total - height).max(0), height, 1);
    }
}

impl View for CertSetView {
    fn bounds(&self) -> Rect {
        self.bounds
    }

    fn set_bounds(&mut self, bounds: Rect) {
        self.bounds = bounds;
    }

    fn draw(&mut self, terminal: &mut Terminal) {
        let width = self.bounds.width_clamped() as usize;
        let height = self.bounds.height_clamped() as usize;

        for y in 0..height {
            let blank = " ".repeat(width);
            let mut buf = DrawBuffer::new(width);
            buf.move_str(0, &blank, colors::NORMAL);
            write_line_to_terminal(terminal, self.bounds.a.x, self.bounds.a.y + y as i16, &buf);
        }

        if width == 0 || height == 0 {
            return;
        }

        self.refresh_if_needed();

        // The scrollbar is the source of truth for the scroll position: it may
        // have been changed directly by a mouse click routed in the main loop
        // (frame children don't receive events via the normal dispatch). Pull
        // its current value into `offset` before drawing.
        self.offset = self.v_scrollbar.borrow().get_value() as usize;

        let total = self.cached_lines.len();
        let max_offset = total.saturating_sub(height);
        if self.offset > max_offset {
            self.offset = max_offset;
        }
        let start = self.offset;
        let end = (start + height).min(total);

        // Scrollbar lives on the border (frame child), so content uses the
        // full interior width.
        for (row, line) in self.cached_lines[start..end].iter().enumerate() {
            draw_colored_line(terminal, self.bounds, row, line, width);
        }

        self.sync_scrollbar();
    }

    fn handle_event(&mut self, event: &mut Event) {
        // The border scrollbar owns keyboard scrolling (arrows, PgUp/PgDn,
        // Home/End) plus click/drag. Let it process the event first.
        self.v_scrollbar.borrow_mut().handle_event(event);

        // The framework ScrollBar does not handle the mouse wheel, so adjust
        // the scrollbar value directly here (the view's `offset` is synced
        // from the scrollbar at the end).
        match event.what {
            EventType::MouseWheelUp => {
                let mut sb = self.v_scrollbar.borrow_mut();
                let v = sb.get_value();
                sb.set_value(v - 2);
                event.clear();
            }
            EventType::MouseWheelDown => {
                let mut sb = self.v_scrollbar.borrow_mut();
                let v = sb.get_value();
                sb.set_value(v + 2);
                event.clear();
            }
            _ => {}
        }

        // The scrollbar is the source of truth for the scroll position.
        self.offset = self.v_scrollbar.borrow().get_value() as usize;
    }

    fn can_focus(&self) -> bool {
        true
    }

    fn get_palette(&self) -> Option<Palette> {
        None
    }

    fn grow_mode(&self) -> GrowFlags {
        self.grow_mode
    }

    fn set_grow_mode(&mut self, grow_mode: GrowFlags) {
        self.grow_mode = grow_mode;
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

// ---------------------------------------------------------------------------
// Shared drawing / scrolling helpers
// ---------------------------------------------------------------------------

fn draw_text_line(terminal: &mut Terminal, bounds: Rect, row: usize, line: &str, width: usize) {
    let clipped: String = line.chars().take(width).collect();
    let padded = format!("{clipped:<width$}");
    let mut buf = DrawBuffer::new(width);
    buf.move_str(0, &padded, colors::NORMAL);
    write_line_to_terminal(terminal, bounds.a.x, bounds.a.y + row as i16, &buf);
}

// ---------------------------------------------------------------------------
// Colored line drawing for CertSetView
// ---------------------------------------------------------------------------

const CT_HDR:    Attr = Attr::new(TvColor::LightCyan,   TvColor::Blue);
const CT_LABEL:  Attr = Attr::new(TvColor::White,       TvColor::Blue);
const CT_DATE:   Attr = Attr::new(TvColor::Yellow,      TvColor::Blue);
const CT_DAYS:   Attr = Attr::new(TvColor::LightGreen,  TvColor::Blue);
const CT_DAYS_BAD: Attr = Attr::new(TvColor::LightRed,  TvColor::Blue);
const CT_PATH:   Attr = Attr::new(TvColor::LightBlue,   TvColor::Blue);
const CT_SEP:    Attr = Attr::new(TvColor::DarkGray,    TvColor::Blue);
const CT_STATUS: Attr = Attr::new(TvColor::LightGreen,  TvColor::Blue);
const CT_CN:     Attr = Attr::new(TvColor::LightMagenta, TvColor::Blue);

/// Render a single line from CertSetView's cached output with syntax coloring.
fn draw_colored_line(terminal: &mut Terminal, bounds: Rect, row: usize, line: &str, width: usize) {
    let trimmed = line.trim_end();

    // Pure separator lines: "===...===" or "---...---"
    if !trimmed.is_empty()
        && trimmed.bytes().all(|b| b == b'=' || b == b'-')
    {
        let padded = format!("{trimmed:<width$}");
        let mut buf = DrawBuffer::new(width);
        buf.move_str(0, &padded, CT_SEP);
        write_line_to_terminal(terminal, bounds.a.x, bounds.a.y + row as i16, &buf);
        return;
    }

    // Section headers
    let is_header = trimmed.starts_with("LEAF CERTIFICATE")
        || trimmed.starts_with("INTERMEDIATE")
        || trimmed.starts_with("PRIVATE KEY")
        || trimmed.starts_with("VERIFICATION");
    if is_header {
        let padded = format!("{trimmed:<width$}");
        let mut buf = DrawBuffer::new(width);
        buf.move_str(0, &padded, CT_HDR);
        write_line_to_terminal(terminal, bounds.a.x, bounds.a.y + row as i16, &buf);
        return;
    }

    // Title line (contains "[cert ...]" / "[key ...]" or "[intermediate(s): ...]")
    if trimmed.contains("[cert ") || trimmed.contains("[key ") {
        let padded = format!("{trimmed:<width$}");
        let mut buf = DrawBuffer::new(width);
        // Write the whole line, then overlay status tags in green
        buf.move_str(0, &padded, CT_LABEL);
        for (tag, attr) in [
            ("[cert OK]",     CT_STATUS),
            ("[key OK]",      CT_STATUS),
            ("[cert --]",     CT_SEP),
            ("[key --]",      CT_SEP),
        ] {
            if let Some(start) = padded.find(tag) {
                buf.move_str(start, tag, attr);
            }
        }
        write_line_to_terminal(terminal, bounds.a.x, bounds.a.y + row as i16, &buf);
        return;
    }

    // Empty lines
    if trimmed.is_empty() {
        let padded = " ".repeat(width).to_string();
        let mut buf = DrawBuffer::new(width);
        buf.move_str(0, &padded, colors::NORMAL);
        write_line_to_terminal(terminal, bounds.a.x, bounds.a.y + row as i16, &buf);
        return;
    }

    // Regular content lines: detect embedded dates and days-remaining.
    let mut buf = DrawBuffer::new(width);
    let padded = format!("{trimmed:<width$}");
    buf.move_str(0, &padded, colors::NORMAL);

    // Highlight date labels and their date values.
    // "Not before", "Not after", "Valid from", "Valid to" variants.
    for label in ["Not before ", "Not before:", "Not after ", "Not after:",
                   "Not valid before ", "Not valid before:",
                   "Valid from ", "Valid from:", "Valid to ", "Valid to:"] {
        if let Some(start) = padded.find(label) {
            let colon = padded[start..].find(':').map(|i| start + i + 1).unwrap_or(start + label.len());
            let full_label = &padded[start..colon];
            buf.move_str(start, full_label, CT_LABEL);
            let val_start = colon;
            let rest = &padded[val_start..];
            let val_len = rest.find('(').or_else(|| rest.find('\n')).unwrap_or(rest.len());
            let val = rest[..val_len].trim_start().trim_end();
            if !val.is_empty() {
                let leading = rest.len() - rest.trim_start().len();
                buf.move_str(val_start + leading, val, CT_DATE);
            }
        }
    }

    // Highlight days-remaining: "(N day(s) remaining)" or "(N day(s) until ...)"
    // or expired variant "(-N day(s) remaining)" / "(expired N day(s) ago)".
    let open = padded.find("(N day");
    if open.is_none() {
        // Try the actual rendered form with a number
        let mut search_from = 0;
        while search_from < padded.len() {
            if let Some(slice_start) = padded[search_from..].find('(') {
                let abs_start = search_from + slice_start;
                let rest = &padded[abs_start + 1..];
                // Check for digit sequence followed by " day(s) remaining)" or " day(s) ago)"
                if let Some(digit_end) = rest.find(|c: char| !c.is_ascii_digit()) {
                    if digit_end > 0 {
                        let after_digits = &rest[digit_end..];
                        let suffix = if let Some(pos) = after_digits.find(" day(s) remaining)") {
                            Some(pos + " day(s) remaining)".len())
                        } else if let Some(pos) = after_digits.find(" day(s) ago)") {
                            Some(pos + " day(s) ago)".len())
                        } else if let Some(pos) = after_digits.find(" day(s) until ") {
                            let until_rest = &after_digits[pos + " day(s) until ".len()..];
                            until_rest.find(')').map(|close| pos + " day(s) until ".len() + close + 1)
                        } else {
                            None
                        };
                        if let Some(total_end_offset) = suffix {
                            let total_start = abs_start;
                            let total_end = abs_start + 1 + digit_end + total_end_offset;
                            let segment = &padded[total_start..total_end];
                            let is_bad = segment.contains('-') || segment.contains("expired");
                            buf.move_str(total_start, segment, if is_bad { CT_DAYS_BAD } else { CT_DAYS });
                            search_from = total_end;
                            continue;
                        }
                    }
                }
                search_from = abs_start + 1;
            } else {
                break;
            }
        }
    }

    // Highlight path-like values inside "(...)" after section headers.
    for label in ["LEAF CERTIFICATE  (", "INTERMEDIATE #", "PRIVATE KEY  ("] {
        if let Some(start) = padded.find(label) {
            let after = &padded[start + label.len()..];
            if let Some(close) = after.find(')') {
                let path_start = start + label.len();
                buf.move_str(path_start, &after[..close], CT_PATH);
            }
        }
    }

    // Highlight field labels at line start (after indentation).
    // The field() format pads names to 11 chars: "Subject    :" or "Issuer     :".
    for keyword in ["Subject", "Issuer", "Serial", "SHA-256", "SHA-256*",
                     "SHA-384", "SHA-512", "Signature Algorithm",
                     "Sig algo", "Pub key", "SANs", "Extensions",
                     "RSA modulus", "RSA pub exp", "Algorithm", "Format",
                     "Version", "RSA modulus"] {
        if let Some(start) = padded.find(keyword) {
            // Find the colon after the keyword (may have padding spaces).
            let rest = &padded[start..];
            if let Some(colon_off) = rest.find(':') {
                let full = &rest[..colon_off + 1];
                buf.move_str(start, full, CT_LABEL);
            }
        }
    }

    // Highlight CN= values everywhere (Subject, Issuer, verification lines, etc.)
    let mut cn_search = 0;
    while cn_search < padded.len() {
        if let Some(pos) = padded[cn_search..].find("CN=") {
            let abs = cn_search + pos;
            let val_end = padded[abs + 3..].find([',', ';', ']', '\n'])
                .map(|e| abs + 3 + e)
                .unwrap_or(padded.len());
            buf.move_str(abs, &padded[abs..val_end], CT_CN);
            cn_search = val_end;
        } else {
            break;
        }
    }

    // Plain "pending..." line
    if trimmed == "pending..." {
        buf.move_str(0, trimmed, CT_SEP);
    }

    write_line_to_terminal(terminal, bounds.a.x, bounds.a.y + row as i16, &buf);
}

fn scroll_handler(event: &mut Event, offset: &mut usize) {
    match event.what {
        EventType::Keyboard => match event.key_code {
            KB_UP => {
                *offset = offset.saturating_sub(4);
                event.clear();
            }
            KB_DOWN => {
                *offset = offset.saturating_add(4);
                event.clear();
            }
            _ => {}
        },
        EventType::MouseWheelUp => {
            *offset = offset.saturating_sub(2);
            event.clear();
        }
        EventType::MouseWheelDown => {
            *offset = offset.saturating_add(2);
            event.clear();
        }
        _ => {}
    }
}

