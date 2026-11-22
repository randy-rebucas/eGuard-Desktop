//! The small windows where a parent types a code from the dashboard. Plain Win32, like the other screens.
//!
//! - "Remove with a code" (spec section 10): the offline removal code shown on the device page.
//! - "Pair eGuard" (spec 4.2: the installer opens eGuard's window and the parent types the code): the pairing code,
//!   and which Windows accounts are the child's.
//!
//! The code is checked by the service (`check`); the window only takes the typing and shows the answer, which may be
//! "wrong code, N more tries" or a lockout.
#![allow(unsafe_code)]

use crate::wide::{from_wide, wide};
use std::cell::RefCell;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{CreateFontW, DEFAULT_CHARSET, FF_SWISS, FW_NORMAL, FW_SEMIBOLD, HFONT, UpdateWindow};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::HiDpi::{DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, GetDpiForSystem, SetProcessDpiAwarenessContext};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{EnableWindow, SetFocus};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AdjustWindowRectEx, BS_DEFPUSHBUTTON, BS_PUSHBUTTON, CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, ES_AUTOHSCROLL,
    ES_UPPERCASE, GetMessageW, GetSystemMetrics, GetWindowTextW, HMENU, IDC_ARROW, IDCANCEL, IDOK, IsDialogMessageW, LoadCursorW, MSG,
    PostQuitMessage, RegisterClassExW, SM_CXSCREEN, SM_CYSCREEN, SW_SHOW, SendMessageW, SetForegroundWindow, SetWindowTextW, ShowWindow,
    TranslateMessage, WM_CLOSE, WM_COMMAND, WM_DESTROY, WM_SETFONT, WNDCLASSEXW, WS_BORDER, WS_CAPTION, WS_CHILD, WS_EX_CLIENTEDGE,
    WS_EX_DLGMODALFRAME, WS_EX_TOPMOST, WS_OVERLAPPED, WS_SYSMENU, WS_TABSTOP, WS_VISIBLE,
};

/// `EM_LIMITTEXT`: codes are 8 letters; a few more for a dash or spaces.
const EM_LIMITTEXT: u32 = 0x00C5;
const MAX_TYPED: usize = 16;

/// Checks what was typed (the code, then the second box's text, empty without one); `Ok` when it was accepted. The
/// words are shown either way.
type Check = Box<dyn FnMut(&str, &str) -> Result<String, String>>;

/// The longest the second box takes (account names, separated by commas).
const MAX_SECOND: usize = 256;

/// The words of one window.
struct Form<'a> {
    class: &'a str,
    title: &'a str,
    heading: &'a str,
    explain: &'a str,
    button: &'a str,
    /// A second box under the code: its label and what's in it to start with.
    second: Option<(&'a str, &'a str)>,
}

struct State {
    edit: HWND,
    second: Option<HWND>,
    status: HWND,
    remove: HWND,
    cancel: HWND,
    check: Check,
    /// The service's answer to a right code, once given.
    accepted: Option<String>,
}

thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
}

fn font(scale: f32, pt: i32, weight: i32) -> HFONT {
    let face = wide("Segoe UI");
    // SAFETY: `face` is zero-terminated; the font lives until the process ends (one window per run).
    unsafe {
        CreateFontW(
            -((pt * 96 / 72) as f32 * scale).round() as i32,
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

/// One child control: its window class, text, styles and id.
struct Control<'a> {
    class: &'a str,
    text: &'a str,
    style: u32,
    ex: u32,
    id: usize,
}

impl<'a> Control<'a> {
    fn new(class: &'a str, text: &'a str) -> Self {
        Self { class, text, style: 0, ex: 0, id: 0 }
    }
}

/// Where a control goes in its window, in pixels.
#[derive(Clone, Copy)]
struct Place {
    x: i32,
    y: i32,
    width: i32,
    height: i32,
}

fn child(parent: HWND, c: &Control<'_>, at: Place, font: HFONT) -> HWND {
    let class = wide(c.class);
    let text = wide(c.text);
    // SAFETY: a child of our own window; the id is passed as the menu handle, as Win32 does for child controls.
    unsafe {
        let hwnd = CreateWindowExW(
            c.ex,
            class.as_ptr(),
            text.as_ptr(),
            WS_CHILD | WS_VISIBLE | c.style,
            at.x,
            at.y,
            at.width,
            at.height,
            parent,
            c.id as HMENU,
            GetModuleHandleW(null()),
            null(),
        );
        SendMessageW(hwnd, WM_SETFONT, font as WPARAM, 1);
        hwnd
    }
}

fn set_text(hwnd: HWND, text: &str) {
    let text = wide(text);
    // SAFETY: our own control; the string is zero-terminated.
    unsafe { SetWindowTextW(hwnd, text.as_ptr()) };
}

/// "Remove with a code". Shows the window until it's closed or a code is accepted. `check` gets what was typed and
/// answers in words: `Ok` when eGuard is being removed. Returns that answer, or `None` when the window was closed
/// without one.
pub fn remove_with_code(mut check: impl FnMut(&str) -> Result<String, String> + 'static) -> std::io::Result<Option<String>> {
    let form = Form {
        class: "eGuardRemoveCode",
        title: "Remove eGuard",
        heading: "Only your parent can remove eGuard",
        explain: "If this computer can't reach eGuard, your parent's dashboard shows a removal code on this computer's page. \
                  Type it here.",
        button: "Remove",
        second: None,
    };
    show(&form, Box::new(move |code, _| check(code)))
}

/// "Pair eGuard": the pairing code from the parent's dashboard, and the child's Windows accounts (`accounts` to start
/// with, separated by commas). `check` gets both and answers in words: `Ok` once paired. Returns that answer, or
/// `None` when the window was closed without pairing.
pub fn pair_with_code(
    accounts: &str,
    check: impl FnMut(&str, &str) -> Result<String, String> + 'static,
) -> std::io::Result<Option<String>> {
    let form = Form {
        class: "eGuardPairCode",
        title: "Pair eGuard",
        heading: "Connect this computer to your family",
        explain: "In the eGuard dashboard, add your child's computer and type the pairing code it shows here.",
        button: "Pair",
        second: Some(("Your child's Windows accounts (the rules apply only in these):", accounts)),
    };
    show(&form, Box::new(check))
}

fn show(form: &Form<'_>, check: Check) -> std::io::Result<Option<String>> {
    let class = wide(form.class);
    // SAFETY: plain calls; a class registered twice in one process fails harmlessly (the first stays).
    let scale = unsafe {
        SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        let wc = WNDCLASSEXW {
            cbSize: size_of::<WNDCLASSEXW>() as u32,
            lpfnWndProc: Some(wndproc),
            hInstance: GetModuleHandleW(null()),
            hCursor: LoadCursorW(null_mut(), IDC_ARROW),
            // COLOR_BTNFACE + 1: the system's dialog colour
            hbrBackground: 16usize as _,
            lpszClassName: class.as_ptr(),
            ..Default::default()
        };
        RegisterClassExW(&raw const wc);
        GetDpiForSystem() as f32 / 96.0
    };
    let px = |v: i32| (v as f32 * scale).round() as i32;
    // The second box and its label take this much more room
    let extra = if form.second.is_some() { px(62) } else { 0 };
    // The inside of the window is laid out; the frame and title bar come on top of it
    let (cw, ch) = (px(440), px(220) + extra);
    let (style, ex_style) = (WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, WS_EX_DLGMODALFRAME | WS_EX_TOPMOST);
    let mut frame = RECT { left: 0, top: 0, right: cw, bottom: ch };
    // SAFETY: `frame` is a writable RECT.
    unsafe { AdjustWindowRectEx(&raw mut frame, style, 0, ex_style) };
    let (w, h) = (frame.right - frame.left, frame.bottom - frame.top);
    // SAFETY: plain metric reads.
    let (sw, sh) = unsafe { (GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN)) };
    let title = wide(form.title);
    // SAFETY: the class is registered; strings are zero-terminated; the window belongs to this thread.
    let hwnd = unsafe {
        CreateWindowExW(
            ex_style,
            class.as_ptr(),
            title.as_ptr(),
            style,
            (sw - w) / 2,
            (sh - h) / 2,
            w,
            h,
            null_mut(),
            null_mut(),
            GetModuleHandleW(null()),
            null(),
        )
    };
    if hwnd.is_null() {
        return Err(crate::last_error());
    }
    let (big, body) = (font(scale, 13, FW_SEMIBOLD as i32), font(scale, 10, FW_NORMAL as i32));
    let m = px(20);
    let inner = cw - 2 * m;
    let at = |x, y, width, height| Place { x, y, width, height };
    child(hwnd, &Control::new("STATIC", form.heading), at(m, m, inner, px(26)), big);
    child(hwnd, &Control::new("STATIC", form.explain), at(m, m + px(32), inner, px(40)), body);
    let edit_style = WS_TABSTOP | WS_BORDER | (ES_UPPERCASE | ES_AUTOHSCROLL) as u32;
    let edit = Control { style: edit_style, ex: WS_EX_CLIENTEDGE, id: 100, ..Control::new("EDIT", "") };
    let edit = child(hwnd, &edit, at(m, m + px(80), px(200), px(28)), big);
    let second = form.second.map(|(label, text)| {
        child(hwnd, &Control::new("STATIC", label), at(m, m + px(116), inner, px(20)), body);
        let style = WS_TABSTOP | WS_BORDER | ES_AUTOHSCROLL as u32;
        let boxed = Control { style, ex: WS_EX_CLIENTEDGE, id: 101, ..Control::new("EDIT", text) };
        let boxed = child(hwnd, &boxed, at(m, m + px(138), inner, px(26)), body);
        // SAFETY: our own control.
        unsafe { SendMessageW(boxed, EM_LIMITTEXT, MAX_SECOND, 0) };
        boxed
    });
    let status = child(hwnd, &Control::new("STATIC", ""), at(m, m + px(114) + extra, inner, px(40)), body);
    let (bw, bh) = (px(100), px(30));
    let row = ch - m - bh;
    let button = |text, id, style: i32| Control { style: WS_TABSTOP | style as u32, id: id as usize, ..Control::new("BUTTON", text) };
    let remove = child(hwnd, &button(form.button, IDOK, BS_DEFPUSHBUTTON), at(cw - m - 2 * bw - px(8), row, bw, bh), body);
    let cancel = child(hwnd, &button("Cancel", IDCANCEL, BS_PUSHBUTTON), at(cw - m - bw, row, bw, bh), body);
    // SAFETY: our own controls and window.
    unsafe {
        SendMessageW(edit, EM_LIMITTEXT, MAX_TYPED, 0);
        ShowWindow(hwnd, SW_SHOW);
        SetForegroundWindow(hwnd);
        SetFocus(edit);
    }
    STATE.with(|s| *s.borrow_mut() = Some(State { edit, second, status, remove, cancel, check, accepted: None }));

    let mut msg = MSG::default();
    // SAFETY: a standard message loop on the thread that owns the window; Tab, Enter and Esc work as in a dialog.
    unsafe {
        while GetMessageW(&raw mut msg, null_mut(), 0, 0) > 0 {
            if IsDialogMessageW(hwnd, &raw const msg) != 0 {
                continue;
            }
            TranslateMessage(&raw const msg);
            DispatchMessageW(&raw const msg);
        }
    }
    Ok(STATE.with(|s| s.borrow_mut().take().and_then(|s| s.accepted)))
}

fn text_of(hwnd: HWND, max: usize) -> String {
    let mut buf = vec![0u16; max + 1];
    // SAFETY: our own control; the buffer's length is passed.
    let n = unsafe { GetWindowTextW(hwnd, buf.as_mut_ptr(), buf.len() as i32) };
    from_wide(&buf[..n.max(0) as usize])
}

/// "Remove" or "Pair" pressed (or Enter): the service checks the code. Its answer shows under the boxes.
fn submit() {
    STATE.with(|s| {
        let mut s = s.borrow_mut();
        let Some(st) = s.as_mut() else { return };
        let typed = text_of(st.edit, MAX_TYPED);
        let second = st.second.map(|h| text_of(h, MAX_SECOND)).unwrap_or_default();
        if typed.trim().is_empty() {
            set_text(st.status, "Type the code first.");
            return;
        }
        set_text(st.status, "Checking…");
        // Painted now: the service may take a few seconds to answer, and nothing paints until it has
        // SAFETY: our own control.
        unsafe { UpdateWindow(st.status) };
        match (st.check)(&typed, &second) {
            Ok(message) => {
                set_text(st.status, &message);
                // SAFETY: our own controls.
                unsafe {
                    EnableWindow(st.edit, 0);
                    if let Some(h) = st.second {
                        EnableWindow(h, 0);
                    }
                    EnableWindow(st.remove, 0);
                    SetFocus(st.cancel);
                }
                set_text(st.cancel, "Close");
                st.accepted = Some(message);
            }
            Err(message) => {
                set_text(st.status, &message);
                set_text(st.edit, "");
                // SAFETY: our own control.
                unsafe { SetFocus(st.edit) };
            }
        }
    });
}

fn accepted() -> bool {
    STATE.with(|s| s.borrow().as_ref().is_some_and(|st| st.accepted.is_some()))
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_COMMAND => {
            match (wparam & 0xFFFF) as i32 {
                // Enter after a right code closes the window, like "Close"
                IDOK if accepted() => unsafe {
                    // SAFETY: our own window.
                    DestroyWindow(hwnd);
                },
                IDOK => submit(),
                // SAFETY: our own window.
                IDCANCEL => unsafe {
                    DestroyWindow(hwnd);
                },
                _ => {}
            }
            0
        }
        WM_CLOSE => {
            // SAFETY: our own window.
            unsafe { DestroyWindow(hwnd) };
            0
        }
        WM_DESTROY => {
            // SAFETY: ends this thread's message loop.
            unsafe { PostQuitMessage(0) };
            0
        }
        // SAFETY: the default handling for everything else.
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}
