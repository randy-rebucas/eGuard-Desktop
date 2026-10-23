//! `eguard-agent`: eGuard in the signed-in session (spec section 3).
//!
//! ```text
//! eguard-agent session [--dev]             started by the service in each session: reports what has the focus
//!                                          and shows the block screen, warnings and overlay (--dev: console mode)
//! eguard-agent pair [CODE] [--name NAME] [--accounts NAME,NAME]
//!                                          pair with a code from the parent dashboard (asks for it if left out),
//!                                          and say which Windows accounts are the child's (asks if left out)
//! eguard-agent accounts [--set NAME,NAME]  the Windows accounts and which are the child's; --set changes that
//! eguard-agent status
//! eguard-agent scan                        look for installed apps now (at most every 2 minutes)
//! eguard-agent preview [block|overlay|warning]
//!                                          show a screen with sample words for a few seconds (development)
//! ```

use eguard_core::ipc::{self, AccountInfo, AppButton, Request, Response, Screen, SessionView, Warning};
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

/// One request on the service's admin pipe (`\\.\pipe\eguard`).
fn ask(request: &Request) -> Result<Response, String> {
    let mut pipe = eguard_win::pipe::connect(ipc::PIPE_NAME).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => "eGuard's service isn't running. Start it (eguard-service run) and try again.".to_owned(),
        std::io::ErrorKind::PermissionDenied => "This account isn't allowed to talk to eGuard's service.".to_owned(),
        _ => format!("couldn't reach eGuard's service: {e}"),
    })?;
    // Any program could have made a pipe by that name first: nothing (a pairing code least of all) goes to anything
    // but eGuard's service beside this exe
    let genuine = eguard_win::pipe::server_pid(&pipe).and_then(process::image_path).is_some_and(|p| same_file(&p, &service_exe()));
    if !genuine {
        return Err(format!("{} isn't served by eGuard's service; another program has taken its name.", ipc::PIPE_NAME));
    }
    pipe.write_all(&ipc::encode(request)).map_err(|e| e.to_string())?;
    let line = ipc::read_line(&mut pipe).map_err(|e| e.to_string())?.ok_or("the service closed the connection")?;
    ipc::decode(&line).map_err(|e| e.to_string())
}

fn prompt(question: &str) -> Result<String, String> {
    print!("{question}");
    std::io::stdout().flush().map_err(|e| e.to_string())?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).map_err(|e| e.to_string())?;
    Ok(line.trim().to_owned())
}

fn names(list: &str) -> Vec<String> {
    list.split(',').map(str::trim).filter(|n| !n.is_empty()).map(str::to_owned).collect()
}

fn list_accounts(set: Option<Vec<String>>) -> Result<Vec<AccountInfo>, String> {
    match ask(&Request::Accounts { set })? {
        Response::Accounts { accounts } => Ok(accounts),
        Response::Error { message } => Err(message),
        _ => Err("unexpected answer from the service".into()),
    }
}

fn show_accounts(accounts: &[AccountInfo]) {
    for a in accounts {
        let role = if a.admin { "administrator" } else { "standard" };
        let rules = if a.enforced { "the child's: rules apply" } else { "not limited" };
        println!("  {:<24} {role:<14} {rules}", a.name);
    }
}

fn pair(args: &[String]) -> Result<(), String> {
    let mut code = None;
    let mut name = None;
    let mut accounts = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--name" => name = Some(it.next().ok_or("--name needs a name")?.clone()),
            "--accounts" => accounts = Some(names(it.next().ok_or("--accounts needs account names, separated by commas")?)),
            c if code.is_none() => code = Some(c.to_owned()),
            other => return Err(format!("unexpected {other}")),
        }
    }
    let code = match code {
        Some(c) => c,
        None => prompt("Pairing code from the parent dashboard: ")?,
    };
    // Which accounts are the child's (spec section 4): asked unless named, standard accounts suggested
    if accounts.is_none() {
        let all = list_accounts(None)?;
        let standard: Vec<&str> = all.iter().filter(|a| !a.admin).map(|a| a.name.as_str()).collect();
        println!("Windows accounts on this computer:");
        for a in &all {
            println!("  {:<24} {}", a.name, if a.admin { "administrator" } else { "standard" });
        }
        println!("eGuard applies your child's rules only in their accounts; the others aren't limited.");
        let typed = prompt(&format!("Your child's accounts, separated by commas [{}]: ", standard.join(", ")))?;
        if !typed.is_empty() {
            accounts = Some(names(&typed));
        }
    }
    match ask(&Request::Pair { code, name, accounts })? {
        Response::Paired { child_name } => {
            println!("Paired. This computer is now {child_name}'s on eGuard.");
            show_accounts(&list_accounts(None)?);
            Ok(())
        }
        Response::Error { message } => Err(message),
        _ => Err("unexpected answer from the service".into()),
    }
}

fn accounts(args: &[String]) -> Result<(), String> {
    let set = match args {
        [] => None,
        [flag, list] if flag == "--set" => Some(names(list)),
        _ => return Err("usage: eguard-agent accounts [--set NAME,NAME]".into()),
    };
    show_accounts(&list_accounts(set)?);
    Ok(())
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

/// One request on this session's pipe, to eGuard's service only. `dev` (started by console mode): the service runs
/// in this session too, so only its exe is checked.
fn ask_session(pipe_name: &str, service: &Path, dev: bool, request: &Request) -> Result<Response, String> {
    let mut pipe = eguard_win::pipe::connect(pipe_name).map_err(|e| e.to_string())?;
    // Anyone could have made a pipe by that name before the service did: only eGuard's service is believed. Its exe
    // isn't enough: the child could start that same exe in console mode in their own session and serve empty views.
    // The real service runs in session 0, where nobody signed in can start anything
    let genuine = eguard_win::pipe::server_pid(&pipe).is_some_and(|pid| {
        process::image_path(pid).is_some_and(|p| same_file(&p, service)) && (dev || process::session_of(pid) == Some(0))
    });
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
                    UiEvent::AskParent(notice) => Some(Request::AskParent { notice }),
                    UiEvent::AskTime(notice) => Some(Request::AskTime { notice }),
                    // An app's button handed the focus over: the heartbeat that tells the service goes now
                    UiEvent::Opened => None,
                };
                // The answer shows on the screen with the next heartbeat, which goes now
                if let Some(request) = request {
                    let _ = ask_session(&pipe_name, &service, dev, &request);
                }
                next = Instant::now();
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => return Err("the screens stopped".into()),
            Err(RecvTimeoutError::Timeout) => {}
        }
        next = Instant::now() + HEARTBEAT_EVERY;
        let heartbeat = Request::Heartbeat { foreground_pid: input::foreground_pid(), idle_ms: input.idle_ms() };
        match ask_session(&pipe_name, &service, dev, &heartbeat) {
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
        apps: Vec::new(),
    };
    let view = match args.first().map(String::as_str) {
        Some("overlay") => {
            // Sample apps: two that start a Windows tool when pressed, a long name, and one never used here (disabled)
            let windir = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
            let app = |name: &str, exe: Option<String>| AppButton { name: name.into(), start: exe.is_some(), exe };
            let apps = vec![
                app("Khan Academy", Some(format!(r"{windir}\System32\notepad.exe"))),
                app("Duolingo", Some(format!(r"{windir}\System32\charmap.exe"))),
                app("Encyclopaedia Britannica for Kids: the Complete Edition", Some(format!(r"{windir}\System32\notepad.exe"))),
                app("Scratch", None),
            ];
            let names: Vec<&str> = apps.iter().map(|a| a.name.as_str()).collect();
            let body = format!("You've used today's 2 hours. You can still use {}.", names.join(", "));
            let mut overlay = screen(0, "Screen time is up for today", &body, false, true);
            overlay.apps = apps;
            SessionView { overlay: Some(overlay), ..SessionView::default() }
        }
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
        Some("accounts") => accounts(&args[1..]),
        Some("status") | None => status(),
        Some("scan") => scan(),
        Some("preview") => preview(&args[1..]),
        Some(_) => Err(
            "usage: eguard-agent session [--dev] | pair [CODE] [--name NAME] [--accounts NAME,NAME] | accounts [--set NAME,NAME] | status | scan | preview [block|overlay|warning]"
                .into(),
        ),
    };
    if let Err(e) = result {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
