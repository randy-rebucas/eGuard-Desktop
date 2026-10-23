//! eGuard's own screens in a session (spec sections 7 and 8), drawn with plain Win32 so they work even when
//! `WebView2` is broken or removed:
//!
//! - the **overlay**: full screen over every monitor, for bedtime and the day's screen time used up, with "Ask for
//!   more time". It stays on top and takes the focus back every second; if something else keeps the focus for
//!   `LOCK_AFTER` anyway (a program forced above it), the session is locked (`LockWorkStation`).
//! - the **block screen**: a window naming the app eGuard just ended and why, with "Ask parent" or "Ask for more
//!   time", and "Close".
//! - the **warning**: a small notice in the corner at 5 and 1 minutes left, gone after a few seconds.
//!
//! The words come from the service (`SessionView`); this only draws them and reports the buttons. Everything runs
//! on one thread with its own message loop; `Ui::show` hands it a new view from any thread.
#![allow(unsafe_code)]

use crate::wide::wide;
use eguard_core::ipc::{Screen, SessionView};
use std::cell::RefCell;
use std::ptr::{null, null_mut};
use std::sync::Mutex;
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{COLORREF, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    BeginPaint, CreateFontW, CreateSolidBrush, DEFAULT_CHARSET, DT_CENTER, DT_LEFT, DT_NOPREFIX, DT_SINGLELINE, DT_VCENTER, DT_WORDBREAK,
    DeleteObject, DrawTextW, EndPaint, FF_SWISS, FW_NORMAL, FW_SEMIBOLD, FillRect, HFONT, InvalidateRect, PAINTSTRUCT, SelectObject,
    SetBkMode, SetTextColor, TRANSPARENT,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Shutdown::LockWorkStation;
use windows_sys::Win32::System::Threading::{AttachThreadInput, GetCurrentThreadId};
use windows_sys::Win32::UI::HiDpi::{DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, GetDpiForSystem, SetProcessDpiAwarenessContext};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    BS_DEFPUSHBUTTON, BS_PUSHBUTTON, BringWindowToTop, CreateWindowExW, DefWindowProcW, DispatchMessageW, GetForegroundWindow, GetMessageW,
    GetSystemMetrics, GetWindowThreadProcessId, HMENU, HWND_TOPMOST, IDC_ARROW, IsDialogMessageW, IsWindowVisible, KillTimer, LoadCursorW,
    MSG, MoveWindow, PostMessageW, RegisterClassExW, SM_CXSCREEN, SM_CXVIRTUALSCREEN, SM_CYSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN,
    SM_YVIRTUALSCREEN, SPI_GETWORKAREA, SW_HIDE, SW_SHOW, SW_SHOWNOACTIVATE, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, SendMessageW,
    SetForegroundWindow, SetTimer, SetWindowPos, ShowWindow, SystemParametersInfoW, TranslateMessage, WM_APP, WM_CLOSE, WM_COMMAND,
    WM_PAINT, WM_SETFONT, WM_TIMER, WNDCLASSEXW, WS_CHILD, WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW, WS_EX_TOPMOST, WS_POPUP, WS_TABSTOP,
};

/// Something else had the focus over the overlay for this long: lock the session.
pub const LOCK_AFTER: Duration = Duration::from_secs(15);
/// How long a warning stays.
const WARNING_FOR: Duration = Duration::from_secs(8);

const WM_VIEW: u32 = WM_APP + 1;
const TIMER_KEEP: usize = 1;
const TIMER_WARNING: usize = 2;

const ID_ASK_PARENT: usize = 101;
const ID_ASK_TIME: usize = 102;
const ID_CLOSE: usize = 103;
const ID_DEV_CLOSE: usize = 104;

const fn rgb(r: u8, g: u8, b: u8) -> COLORREF {
    r as u32 | (g as u32) << 8 | (b as u32) << 16
}
const OVERLAY_BG: COLORREF = rgb(15, 23, 42);
const OVERLAY_TEXT: COLORREF = rgb(241, 245, 249);
const OVERLAY_MUTED: COLORREF = rgb(148, 163, 184);
const CARD_BG: COLORREF = rgb(255, 255, 255);
const CARD_TEXT: COLORREF = rgb(15, 23, 42);
const CARD_MUTED: COLORREF = rgb(71, 85, 105);
const ACCENT: COLORREF = rgb(37, 99, 235);

/// A button on one of the screens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiEvent {
    /// "Ask parent" on the block screen with this id.
    AskParent(u64),
    /// "Ask for more time" on a block screen (`Some`) or the overlay.
    AskTime(Option<u64>),
}

/// The newest view, handed from the agent's loop to the UI thread.
static VIEW: Mutex<Option<SessionView>> = Mutex::new(None);

/// The UI thread. Dropping this doesn't stop it: it lives as long as the agent.
#[derive(Debug)]
pub struct Ui {
    /// Where new views are posted (the overlay window, which always exists).
    post_to: isize,
}

impl Ui {
    /// Starts the UI thread. `dev` (console mode on a developer's PC): the overlay gets a close button and never
    /// locks the session.
    pub fn start(dev: bool, events: Sender<UiEvent>) -> std::io::Result<Self> {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::Builder::new().name("ui".into()).spawn(move || match create(dev, events) {
            Ok(post_to) => {
                let _ = tx.send(Ok(post_to));
                run_loop();
            }
            Err(e) => {
                let _ = tx.send(Err(e));
            }
        })?;
        let post_to = rx.recv().map_err(|_| std::io::Error::other("the UI thread stopped"))??;
        Ok(Self { post_to })
    }

    /// Shows `view` (the same view again changes nothing).
    pub fn show(&self, view: SessionView) {
        if let Ok(mut v) = VIEW.lock() {
            *v = Some(view);
        }
        // SAFETY: the window belongs to the UI thread, which never destroys it; posting is thread-safe.
        unsafe { PostMessageW(self.post_to as HWND, WM_VIEW, 0, 0) };
    }
}

/// Whether the window with the focus is one of this process's (so the agent tells the service "eGuard's own screen").
pub fn own_window_focused() -> bool {
    crate::input::foreground_pid() == Some(crate::process::current_pid())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Overlay,
    Block,
    Warning,
}

struct Window {
    hwnd: HWND,
    buttons: Vec<(usize, HWND)>,
}

struct State {
    dev: bool,
    events: Sender<UiEvent>,
    overlay: Window,
    block: Window,
    warning: Window,
    title_font: HFONT,
    big_font: HFONT,
    body_font: HFONT,
    scale: f32,
    view: SessionView,
    /// The block screen the child closed.
    dismissed_block: u64,
    /// The warning on show (or last shown), by id.
    warning_id: u64,
    /// Console mode: the child (developer) closed the overlay for this pause.
    dev_dismissed_overlay: bool,
    /// Since when something else has had the focus while the overlay is up.
    unfocused_since: Option<Instant>,
}

thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
}

/// Runs `f` on the state, unless it's already borrowed (a message sent while the UI thread is inside `f`).
fn with<R>(f: impl FnOnce(&mut State) -> R) -> Option<R> {
    STATE.with(|s| s.try_borrow_mut().ok().and_then(|mut s| s.as_mut().map(f)))
}

fn px(scale: f32, v: i32) -> i32 {
    (v as f32 * scale).round() as i32
}

fn font(scale: f32, pt: i32, weight: i32) -> HFONT {
    let face = wide("Segoe UI");
    // SAFETY: `face` is zero-terminated; the font lives as long as the UI thread.
    unsafe {
        CreateFontW(
            -px(scale, pt * 96 / 72),
            0,
            0,
            0,
            weight,
            0,
            0,
            0,
            u32::from(DEFAULT_CHARSET),
            0,
            0,
            5, // CLEARTYPE_QUALITY
            u32::from(FF_SWISS),
            face.as_ptr(),
        )
    }
}

fn class_name() -> Vec<u16> {
    wide("eGuardScreen")
}

fn create_window(ex: u32, x: i32, y: i32, w: i32, h: i32) -> std::io::Result<HWND> {
    let class = class_name();
    let title = wide("eGuard");
    // SAFETY: the class is registered; strings are zero-terminated; the window belongs to this thread.
    let hwnd = unsafe {
        CreateWindowExW(ex, class.as_ptr(), title.as_ptr(), WS_POPUP, x, y, w, h, null_mut(), null_mut(), GetModuleHandleW(null()), null())
    };
    if hwnd.is_null() { Err(crate::last_error()) } else { Ok(hwnd) }
}

fn create_button(parent: HWND, id: usize, text: &str, default: bool) -> HWND {
    let class = wide("BUTTON");
    let text = wide(text);
    let style = WS_CHILD | WS_TABSTOP | if default { BS_DEFPUSHBUTTON as u32 } else { BS_PUSHBUTTON as u32 };
    // SAFETY: a child of our own window; the id is passed as the menu handle, as Win32 does for child controls.
    unsafe { CreateWindowExW(0, class.as_ptr(), text.as_ptr(), style, 0, 0, 10, 10, parent, id as HMENU, GetModuleHandleW(null()), null()) }
}

fn create(dev: bool, events: Sender<UiEvent>) -> std::io::Result<isize> {
    // SAFETY: plain calls; registering a class twice in one process fails harmlessly (the first stays).
    let scale = unsafe {
        SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        let class = class_name();
        let wc = WNDCLASSEXW {
            cbSize: size_of::<WNDCLASSEXW>() as u32,
            lpfnWndProc: Some(wndproc),
            hInstance: GetModuleHandleW(null()),
            hCursor: LoadCursorW(null_mut(), IDC_ARROW),
            lpszClassName: class.as_ptr(),
            ..Default::default()
        };
        RegisterClassExW(&raw const wc);
        GetDpiForSystem() as f32 / 96.0
    };
    let overlay = create_window(WS_EX_TOPMOST | WS_EX_TOOLWINDOW, 0, 0, 100, 100)?;
    let block = create_window(WS_EX_TOPMOST | WS_EX_TOOLWINDOW, 0, 0, px(scale, 540), px(scale, 280))?;
    let warning = create_window(WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE, 0, 0, px(scale, 400), px(scale, 72))?;
    let mut overlay_buttons = vec![(ID_ASK_TIME, create_button(overlay, ID_ASK_TIME, "Ask for more time", true))];
    if dev {
        overlay_buttons.push((ID_DEV_CLOSE, create_button(overlay, ID_DEV_CLOSE, "Close (development build)", false)));
    }
    let block_buttons = vec![
        (ID_ASK_PARENT, create_button(block, ID_ASK_PARENT, "Ask parent", true)),
        (ID_ASK_TIME, create_button(block, ID_ASK_TIME, "Ask for more time", true)),
        (ID_CLOSE, create_button(block, ID_CLOSE, "Close", false)),
    ];
    let state = State {
        dev,
        events,
        overlay: Window { hwnd: overlay, buttons: overlay_buttons },
        block: Window { hwnd: block, buttons: block_buttons },
        warning: Window { hwnd: warning, buttons: Vec::new() },
        title_font: font(scale, 28, FW_SEMIBOLD as i32),
        big_font: font(scale, 17, FW_SEMIBOLD as i32),
        body_font: font(scale, 11, FW_NORMAL as i32),
        scale,
        view: SessionView::default(),
        dismissed_block: 0,
        warning_id: 0,
        dev_dismissed_overlay: false,
        unfocused_since: None,
    };
    let body_font = state.body_font;
    for w in [&state.overlay, &state.block] {
        for &(_, b) in &w.buttons {
            // SAFETY: our own button; the font outlives it.
            unsafe { SendMessageW(b, WM_SETFONT, body_font as WPARAM, 1) };
        }
    }
    STATE.with(|s| *s.borrow_mut() = Some(state));
    // SAFETY: our own window; the timer runs on this thread.
    unsafe { SetTimer(overlay, TIMER_KEEP, 1000, None) };
    Ok(overlay as isize)
}

fn run_loop() {
    let mut msg = MSG::default();
    // SAFETY: a standard message loop on the thread that owns the windows.
    unsafe {
        while GetMessageW(&raw mut msg, null_mut(), 0, 0) > 0 {
            // Tab and Enter move between and press the buttons
            let active = GetForegroundWindow();
            if !active.is_null() && IsDialogMessageW(active, &raw const msg) != 0 {
                continue;
            }
            TranslateMessage(&raw const msg);
            DispatchMessageW(&raw const msg);
        }
    }
}

/// Brings `hwnd` to the front. Windows lets only the program the user is using take the focus, so this borrows the
/// focused window's input queue for the moment it takes (documented `AttachThreadInput` use).
fn force_foreground(hwnd: HWND) {
    // SAFETY: plain calls on our own window and the current foreground's thread id; detached again at once.
    unsafe {
        let fg = GetForegroundWindow();
        if fg == hwnd {
            return;
        }
        let fg_thread = if fg.is_null() { 0 } else { GetWindowThreadProcessId(fg, null_mut()) };
        let me = GetCurrentThreadId();
        if fg_thread != 0 && fg_thread != me {
            AttachThreadInput(me, fg_thread, 1);
            BringWindowToTop(hwnd);
            SetForegroundWindow(hwnd);
            AttachThreadInput(me, fg_thread, 0);
        } else {
            BringWindowToTop(hwnd);
            SetForegroundWindow(hwnd);
        }
    }
}

fn keep_on_top(hwnd: HWND) {
    // SAFETY: our own window.
    unsafe { SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE) };
}

fn work_area() -> RECT {
    let mut r = RECT::default();
    // SAFETY: `r` is a live RECT, which SPI_GETWORKAREA fills.
    unsafe { SystemParametersInfoW(SPI_GETWORKAREA, 0, (&raw mut r).cast(), 0) };
    r
}

fn show(hwnd: HWND, visible: bool, activate: bool) {
    // SAFETY: our own window.
    unsafe {
        let shown = IsWindowVisible(hwnd) != 0;
        if visible && !shown {
            ShowWindow(hwnd, if activate { SW_SHOW } else { SW_SHOWNOACTIVATE });
        } else if !visible && shown {
            ShowWindow(hwnd, SW_HIDE);
        }
        InvalidateRect(hwnd, null(), 1);
    }
}

/// Where a row of buttons goes: centered on `x`, or ending at `x`.
#[derive(Clone, Copy)]
enum Align {
    Center(i32),
    Right(i32),
}

/// Lays out a screen's buttons in a row at `row_y`, only those the screen offers (none but Close once it was asked).
fn place_buttons(w: &Window, s: &Screen, scale: f32, align: Align, row_y: i32) {
    let wanted = |id: usize| match id {
        _ if s.asked.is_some() && id != ID_CLOSE && id != ID_DEV_CLOSE => false,
        ID_ASK_PARENT => s.ask_parent,
        ID_ASK_TIME => s.ask_time,
        _ => true,
    };
    let (h, gap) = (px(scale, 36), px(scale, 10));
    let width = |id: usize| {
        px(
            scale,
            if id == ID_DEV_CLOSE {
                210
            } else if id == ID_CLOSE {
                96
            } else {
                170
            },
        )
    };
    let visible: Vec<(usize, HWND)> = w.buttons.iter().copied().filter(|(id, _)| wanted(*id)).collect();
    let total: i32 = visible.iter().map(|(id, _)| width(*id)).sum::<i32>() + gap * (visible.len() as i32 - 1).max(0);
    let mut x = match align {
        Align::Center(cx) => cx - total / 2,
        Align::Right(right) => right - total,
    };
    for &(_, b) in &w.buttons {
        // SAFETY: our own buttons.
        unsafe { ShowWindow(b, SW_HIDE) };
    }
    for (id, b) in visible {
        // SAFETY: our own buttons.
        unsafe {
            MoveWindow(b, x, row_y, width(id), h, 1);
            ShowWindow(b, SW_SHOW);
        }
        x += width(id) + gap;
    }
}

/// Applies the newest view: shows, hides and lays out the three screens.
fn apply() {
    let Some(view) = VIEW.lock().ok().and_then(|mut v| v.take()) else { return };
    // Decide under the borrow; call Windows after it (showing a window sends messages back here)
    let Some(plan) = with(|st| {
        if view.overlay.is_none() {
            st.dev_dismissed_overlay = false;
        }
        let overlay = view.overlay.clone().filter(|_| !st.dev_dismissed_overlay);
        let block = view.block.clone().filter(|b| b.id != st.dismissed_block);
        let new_warning = view.warning.clone().filter(|w| w.id != st.warning_id);
        if let Some(w) = &new_warning {
            st.warning_id = w.id;
        }
        let block_is_new = block.as_ref().is_some_and(|b| st.view.block.as_ref().is_none_or(|old| old.id != b.id));
        st.view = SessionView { overlay: overlay.clone(), block: block.clone(), warning: new_warning.clone().or(st.view.warning.clone()) };
        if overlay.is_none() {
            st.unfocused_since = None;
        }
        (st.overlay.hwnd, st.block.hwnd, st.warning.hwnd, overlay, block, block_is_new, new_warning.is_some(), st.scale)
    }) else {
        return;
    };
    let (overlay_hwnd, block_hwnd, warning_hwnd, overlay, block, block_is_new, new_warning, scale) = plan;

    if let Some(s) = &overlay {
        // SAFETY: plain metric reads.
        let (vx, vy, vw, vh, pw, ph) = unsafe {
            (
                GetSystemMetrics(SM_XVIRTUALSCREEN),
                GetSystemMetrics(SM_YVIRTUALSCREEN),
                GetSystemMetrics(SM_CXVIRTUALSCREEN),
                GetSystemMetrics(SM_CYVIRTUALSCREEN),
                GetSystemMetrics(SM_CXSCREEN),
                GetSystemMetrics(SM_CYSCREEN),
            )
        };
        // SAFETY: our own window, over every monitor.
        unsafe { MoveWindow(overlay_hwnd, vx, vy, vw, vh, 1) };
        // The words sit in the middle of the main monitor, which starts at (0, 0) in screen coordinates
        let (cx, cy) = (-vx + pw / 2, -vy + ph / 2);
        let _ = with(|st| place_buttons(&st.overlay, s, scale, Align::Center(cx), cy + px(scale, 40)));
        show(overlay_hwnd, true, true);
        keep_on_top(overlay_hwnd);
        force_foreground(overlay_hwnd);
    } else {
        show(overlay_hwnd, false, false);
    }

    if let Some(b) = &block {
        let wa = work_area();
        let (w, h) = (px(scale, 540), px(scale, 280));
        let (x, y) = (wa.left + (wa.right - wa.left - w) / 2, wa.top + (wa.bottom - wa.top - h) / 2);
        // SAFETY: our own window.
        unsafe { MoveWindow(block_hwnd, x, y, w, h, 1) };
        let _ = with(|st| place_buttons(&st.block, b, scale, Align::Right(w - px(scale, 28)), h - px(scale, 28) - px(scale, 36)));
        // Over the overlay's area only when there's no overlay: the overlay says it all
        let visible = overlay.is_none();
        show(block_hwnd, visible, block_is_new);
        if visible && block_is_new {
            keep_on_top(block_hwnd);
            force_foreground(block_hwnd);
        }
    } else {
        show(block_hwnd, false, false);
    }

    if new_warning {
        let wa = work_area();
        let (w, h) = (px(scale, 400), px(scale, 72));
        // SAFETY: our own window, in the corner of the main monitor's work area; shown without taking the focus.
        unsafe {
            MoveWindow(warning_hwnd, wa.right - w - px(scale, 16), wa.bottom - h - px(scale, 16), w, h, 1);
            SetTimer(warning_hwnd, TIMER_WARNING, WARNING_FOR.as_millis() as u32, None);
        }
        show(warning_hwnd, true, false);
        keep_on_top(warning_hwnd);
    }
}

/// Every second while the overlay is up: back on top, the focus back, and the lock backstop.
fn keep() {
    let Some((hwnd, dev, since)) = with(|st| (st.overlay.hwnd, st.dev, st.unfocused_since)) else { return };
    // SAFETY: our own window.
    if unsafe { IsWindowVisible(hwnd) } == 0 {
        let has_overlay = with(|st| st.view.overlay.is_some()).unwrap_or(false);
        if !has_overlay {
            return;
        }
        // Someone hid it: show it again
        show(hwnd, true, true);
    }
    keep_on_top(hwnd);
    force_foreground(hwnd);
    let ours = own_window_focused();
    let now = Instant::now();
    let since = if ours { None } else { Some(since.unwrap_or(now)) };
    let _ = with(|st| st.unfocused_since = since);
    if since.is_some_and(|t| now - t >= LOCK_AFTER) {
        let _ = with(|st| st.unfocused_since = None);
        if !dev {
            // SAFETY: locks this session; the overlay is there again when it's unlocked.
            unsafe { LockWorkStation() };
        }
    }
}

fn paint(hwnd: HWND) {
    let mut ps = PAINTSTRUCT::default();
    // SAFETY: WM_PAINT on our own window: BeginPaint/EndPaint pair; fonts and brushes are ours.
    unsafe {
        let hdc = BeginPaint(hwnd, &raw mut ps);
        STATE.with(|s| {
            let Ok(s) = s.try_borrow() else { return };
            let Some(st) = s.as_ref() else { return };
            let kind = if hwnd == st.overlay.hwnd {
                Kind::Overlay
            } else if hwnd == st.block.hwnd {
                Kind::Block
            } else {
                Kind::Warning
            };
            let mut client = RECT::default();
            windows_sys::Win32::UI::WindowsAndMessaging::GetClientRect(hwnd, &raw mut client);
            let bg = match kind {
                Kind::Block => CARD_BG,
                _ => OVERLAY_BG,
            };
            let brush = CreateSolidBrush(bg);
            FillRect(hdc, &raw const client, brush);
            DeleteObject(brush);
            SetBkMode(hdc, TRANSPARENT as i32);
            let text = |font: HFONT, color: COLORREF, s: &str, mut r: RECT, flags: u32| {
                SelectObject(hdc, font);
                SetTextColor(hdc, color);
                let w: Vec<u16> = s.encode_utf16().collect();
                DrawTextW(hdc, w.as_ptr(), w.len() as i32, &raw mut r, flags | DT_NOPREFIX);
            };
            let p = |v: i32| px(st.scale, v);
            match kind {
                Kind::Overlay => {
                    let Some(s) = &st.view.overlay else { return };
                    let (vx, vy) = (GetSystemMetrics(SM_XVIRTUALSCREEN), GetSystemMetrics(SM_YVIRTUALSCREEN));
                    let (cx, cy) = (-vx + GetSystemMetrics(SM_CXSCREEN) / 2, -vy + GetSystemMetrics(SM_CYSCREEN) / 2);
                    let col = |top: i32, bottom: i32| RECT { left: cx - p(320), right: cx + p(320), top: cy + top, bottom: cy + bottom };
                    text(st.title_font, OVERLAY_TEXT, &s.title, col(p(-130), p(-60)), DT_CENTER | DT_SINGLELINE | DT_VCENTER);
                    text(st.body_font, OVERLAY_MUTED, &s.body, col(p(-50), p(30)), DT_CENTER | DT_WORDBREAK);
                    if let Some(a) = &s.asked {
                        text(st.body_font, OVERLAY_TEXT, a, col(p(90), p(150)), DT_CENTER | DT_WORDBREAK);
                    }
                }
                Kind::Block => {
                    let Some(s) = &st.view.block else { return };
                    let accent = CreateSolidBrush(ACCENT);
                    let bar = RECT { left: 0, top: 0, right: client.right, bottom: p(6) };
                    FillRect(hdc, &raw const bar, accent);
                    DeleteObject(accent);
                    let row = |top: i32, bottom: i32| RECT { left: p(28), right: client.right - p(28), top, bottom };
                    text(st.big_font, CARD_TEXT, &s.title, row(p(30), p(72)), DT_LEFT | DT_SINGLELINE | DT_VCENTER);
                    text(st.body_font, CARD_MUTED, &s.body, row(p(80), p(150)), DT_LEFT | DT_WORDBREAK);
                    if let Some(a) = &s.asked {
                        text(st.body_font, CARD_TEXT, a, row(p(158), p(200)), DT_LEFT | DT_WORDBREAK);
                    }
                }
                Kind::Warning => {
                    let Some(w) = &st.view.warning else { return };
                    let r = RECT { left: p(20), right: client.right - p(20), top: 0, bottom: client.bottom };
                    text(st.body_font, OVERLAY_TEXT, &w.text, r, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
                }
            }
        });
        EndPaint(hwnd, &raw const ps);
    }
}

fn command(hwnd: HWND, id: usize) {
    let Some(()) = with(|st| {
        let is_overlay = hwnd == st.overlay.hwnd;
        match id {
            ID_ASK_PARENT => {
                if let Some(b) = &st.view.block {
                    let _ = st.events.send(UiEvent::AskParent(b.id));
                }
            }
            ID_ASK_TIME if is_overlay => {
                let _ = st.events.send(UiEvent::AskTime(None));
            }
            ID_ASK_TIME => {
                if let Some(b) = &st.view.block {
                    let _ = st.events.send(UiEvent::AskTime(Some(b.id)));
                }
            }
            ID_CLOSE => {
                if let Some(b) = &st.view.block {
                    st.dismissed_block = b.id;
                }
                st.view.block = None;
            }
            ID_DEV_CLOSE => {
                st.dev_dismissed_overlay = true;
                st.view.overlay = None;
            }
            _ => {}
        }
    }) else {
        return;
    };
    if matches!(id, ID_CLOSE | ID_DEV_CLOSE) {
        show(hwnd, false, false);
    }
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_VIEW => {
            apply();
            0
        }
        WM_PAINT => {
            paint(hwnd);
            0
        }
        WM_COMMAND => {
            command(hwnd, wparam & 0xFFFF);
            0
        }
        WM_TIMER if wparam == TIMER_KEEP => {
            keep();
            0
        }
        WM_TIMER if wparam == TIMER_WARNING => {
            // SAFETY: our own window and timer.
            unsafe { KillTimer(hwnd, TIMER_WARNING) };
            show(hwnd, false, false);
            0
        }
        WM_CLOSE => {
            // Alt+F4: the block screen and the warning close; the overlay doesn't (except in a development build)
            let (overlay, dev) = with(|st| (st.overlay.hwnd, st.dev)).unwrap_or((null_mut(), false));
            if hwnd == overlay {
                if dev {
                    command(hwnd, ID_DEV_CLOSE);
                }
            } else if with(|st| hwnd == st.block.hwnd).unwrap_or(false) {
                command(hwnd, ID_CLOSE);
            } else {
                show(hwnd, false, false);
            }
            0
        }
        // SAFETY: everything else goes to Windows' default handling.
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eguard_core::ipc::Warning;

    /// Shows the block screen and a warning for a moment, then hides them. Run by hand (it draws on the screen):
    /// `cargo test -p eguard-win ui -- --ignored`.
    #[test]
    #[ignore = "draws on the screen"]
    fn block_screen_and_warning_show_and_hide() {
        let (tx, rx) = std::sync::mpsc::channel();
        let ui = Ui::start(true, tx).unwrap();
        let block = Screen {
            id: 7,
            title: "Counter-Strike 2 is blocked".into(),
            body: "Your parent blocked this app. You can ask them to allow it.".into(),
            ask_parent: true,
            ask_time: false,
            asked: None,
        };
        ui.show(SessionView {
            block: Some(block),
            warning: Some(Warning { id: 1, text: "5 minutes of gaming time left today.".into() }),
            ..SessionView::default()
        });
        std::thread::sleep(Duration::from_secs(3));
        assert!(own_window_focused());
        ui.show(SessionView::default());
        std::thread::sleep(Duration::from_millis(300));
        assert!(rx.try_recv().is_err());
    }
}
