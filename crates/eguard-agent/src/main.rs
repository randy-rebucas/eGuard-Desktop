//! `eguard-agent`: eGuard in the signed-in session (spec section 3).
//!
//! ```text
//! eguard-agent session [--dev]             started by the service in each session: reports what has the focus
//!                                          and shows the block screen, warnings and overlay (--dev: console mode)
//! eguard-agent pair [CODE] [--name NAME]   pair with a code from the parent dashboard (asks for it if left out)
//! eguard-agent status
//! eguard-agent scan                        look for installed apps now (at most every 2 minutes)
//! eguard-agent preview [block|overlay|warning]
//!                                          show a screen with sample words for a few seconds (development)
//! ```

use eguard_core::ipc::{self, Request, Response, Screen, SessionView, Warning};
use eguard_win::input::{self, InputWatch};
use eguard_win::process;
use eguard_win::ui::{Ui, UiEvent};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::RecvTimeoutError;
use std::time::{Duration, Instant};

/// How often the agent reports to the service.
const HEARTBEAT_EVERY: Duration = Duration::from_secs(1);
/// With no service answering this long, the agent exits (the service starts it again when it's back).
const GIVE_UP_AFTER: Duration = Duration::from_secs(5 * 60);

fn ask(request: &Request) -> Result<Response, String> {
    let mut pipe = eguard_win::pipe::connect(ipc::PIPE_NAME).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => "eGuard's service isn't running. Start it (eguard-service run) and try again.".to_owned(),
        std::io::ErrorKind::PermissionDenied => "This account isn't allowed to talk to eGuard's service.".to_owned(),
        _ => format!("couldn't reach eGuard's service: {e}"),
    })?;
    pipe.write_all(&ipc::encode(request)).map_err(|e| e.to_string())?;
    let line = ipc::read_line(&mut pipe).map_err(|e| e.to_string())?.ok_or("the service closed the connection")?;
    ipc::decode(&line).map_err(|e| e.to_string())
}

fn pair(args: &[String]) -> Result<(), String> {
    let mut code = None;
    let mut name = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--name" => name = Some(it.next().ok_or("--name needs a name")?.clone()),
            c if code.is_none() => code = Some(c.to_owned()),
            other => return Err(format!("unexpected {other}")),
        }
    }
    let code = if let Some(c) = code {
        c
    } else {
        print!("Pairing code from the parent dashboard: ");
        std::io::stdout().flush().map_err(|e| e.to_string())?;
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line).map_err(|e| e.to_string())?;
        line.trim().to_owned()
    };
    match ask(&Request::Pair { code, name })? {
        Response::Paired { child_name } => {
            println!("Paired. This computer is now {child_name}'s on eGuard.");
            Ok(())
        }
        Response::Error { message } => Err(message),
        _ => Err("unexpected answer from the service".into()),
    }
}

fn status() -> Result<(), String> {
    match ask(&Request::Status)? {
        Response::Status(s) => {
            if s.paired {
                println!("Paired: {} ({})", s.child_name.as_deref().unwrap_or("?"), s.device_id.as_deref().unwrap_or("?"));
                println!("Last sync: {}", s.last_sync_at.as_deref().unwrap_or("not yet"));
                if !s.authorized {
                    println!("eGuard is refusing this computer's key. Protection carries on; ask the parent to check the dashboard.");
                }
            } else {
                println!("Not paired. Run: eguard-agent pair");
            }
            match (s.apps_reported, s.last_scan_at.as_deref()) {
                (Some(n), Some(at)) => println!("Apps reported: {n} (last scan {at})"),
                _ if s.paired => println!("Apps: not scanned yet"),
                _ => {}
            }
            println!("Server: {}  ·  waiting to send: {}", s.server, s.queued);
            Ok(())
        }
        Response::Error { message } => Err(message),
        _ => Err("unexpected answer from the service".into()),
    }
}

fn scan() -> Result<(), String> {
    match ask(&Request::Scan)? {
        Response::Status(s) if s.paired => {
            println!("eGuard will look for installed apps within a couple of minutes. Run `eguard-agent status` to see when it has.");
            Ok(())
        }
        Response::Status(_) => Err("This computer isn't paired yet. Run: eguard-agent pair".into()),
        Response::Error { message } => Err(message),
        _ => Err("unexpected answer from the service".into()),
    }
}

/// `eguard-service.exe` next to this exe: the only process the agent takes its screens from.
fn service_exe() -> PathBuf {
    std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join("eguard-service.exe"))).unwrap_or_default()
}

fn same_file(a: &Path, b: &Path) -> bool {
    a.to_string_lossy().eq_ignore_ascii_case(&b.to_string_lossy())
}

/// One request on this session's pipe, to eGuard's service only.
fn ask_session(pipe_name: &str, service: &Path, request: &Request) -> Result<Response, String> {
    let mut pipe = eguard_win::pipe::connect(pipe_name).map_err(|e| e.to_string())?;
    // Anyone could have made a pipe by that name before the service did: only eGuard's service is believed
    let genuine = eguard_win::pipe::server_pid(&pipe).and_then(process::image_path).is_some_and(|p| same_file(&p, service));
    if !genuine {
        return Err("the session pipe isn't eGuard's service".into());
    }
    pipe.write_all(&ipc::encode(request)).map_err(|e| e.to_string())?;
    let line = ipc::read_line(&mut pipe).map_err(|e| e.to_string())?.ok_or("the service closed the connection")?;
    ipc::decode(&line).map_err(|e| e.to_string())
}

/// The agent in a session: a heartbeat every second, the screens the service asks for, and the child's buttons.
fn session(args: &[String]) -> Result<(), String> {
    let dev = args.iter().any(|a| a == "--dev");
    let id = process::session_of(process::current_pid()).ok_or("couldn't tell which session this is")?;
    let pipe_name = ipc::session_pipe_name(id);
    let service = service_exe();
    let (tx, rx) = std::sync::mpsc::channel();
    let ui = Ui::start(dev, tx).map_err(|e| format!("couldn't start the screens: {e}"))?;
    let mut input = InputWatch::new();
    let mut last_answer = Instant::now();
    let mut next = Instant::now();
    loop {
        // A button, or the next heartbeat, whichever comes first
        match rx.recv_timeout(next.saturating_duration_since(Instant::now())) {
            Ok(event) => {
                let request = match event {
                    UiEvent::AskParent(notice) => Request::AskParent { notice },
                    UiEvent::AskTime(notice) => Request::AskTime { notice },
                };
                // The answer shows on the screen with the next heartbeat, which goes now
                let _ = ask_session(&pipe_name, &service, &request);
                next = Instant::now();
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => return Err("the screens stopped".into()),
            Err(RecvTimeoutError::Timeout) => {}
        }
        next = Instant::now() + HEARTBEAT_EVERY;
        let heartbeat = Request::Heartbeat { foreground_pid: input::foreground_pid(), idle_ms: input.idle_ms() };
        match ask_session(&pipe_name, &service, &heartbeat) {
            Ok(Response::Session(view)) => {
                last_answer = Instant::now();
                ui.show(view);
            }
            // Keep showing what was shown: a service that's away doesn't lift a pause
            _ if last_answer.elapsed() > GIVE_UP_AFTER => return Ok(()),
            _ => {}
        }
    }
}

/// Shows one screen with sample words, to check how it looks.
fn preview(args: &[String]) -> Result<(), String> {
    let (tx, rx) = std::sync::mpsc::channel();
    let ui = Ui::start(true, tx).map_err(|e| e.to_string())?;
    let screen = |id, title: &str, body: &str, parent, time| Screen {
        id,
        title: title.into(),
        body: body.into(),
        ask_parent: parent,
        ask_time: time,
        asked: None,
    };
    let view = match args.first().map(String::as_str) {
        Some("overlay") => SessionView {
            overlay: Some(screen(
                0,
                "Screen time is up for today",
                "You've used today's 2 hours. You can still use Khan Academy.",
                false,
                true,
            )),
            ..SessionView::default()
        },
        Some("warning") => {
            SessionView { warning: Some(Warning { id: 1, text: "5 minutes of gaming time left today.".into() }), ..SessionView::default() }
        }
        _ => SessionView {
            block: Some(screen(
                1,
                "Counter-Strike 2 is blocked",
                "Your parent blocked this app. You can ask them to allow it.",
                true,
                false,
            )),
            ..SessionView::default()
        },
    };
    ui.show(view);
    match rx.recv_timeout(Duration::from_secs(8)) {
        Ok(e) => println!("pressed: {e:?}"),
        Err(_) => println!("no button pressed"),
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("session") => session(&args[1..]),
        Some("pair") => pair(&args[1..]),
        Some("status") | None => status(),
        Some("scan") => scan(),
        Some("preview") => preview(&args[1..]),
        Some(_) => {
            Err("usage: eguard-agent session [--dev] | pair [CODE] [--name NAME] | status | scan | preview [block|overlay|warning]".into())
        }
    };
    if let Err(e) = result {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
