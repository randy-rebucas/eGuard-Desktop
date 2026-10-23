//! `eguard-agent`: eGuard in the signed-in session. The real one is a Tauri window started by the service in each
//! session (spec section 3); until then this console pairs the computer and shows its status, over the pipe.
//!
//! ```text
//! eguard-agent pair [CODE] [--name NAME]   pair with a code from the parent dashboard (asks for it if left out)
//! eguard-agent status
//! ```

use eguard_core::ipc::{self, Request, Response};
use std::io::{BufRead, Write};

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
        Response::Status(_) => Err("unexpected answer from the service".into()),
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
            println!("Server: {}  ·  waiting to send: {}", s.server, s.queued);
            Ok(())
        }
        Response::Error { message } => Err(message),
        Response::Paired { .. } => Err("unexpected answer from the service".into()),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("pair") => pair(&args[1..]),
        Some("status") | None => status(),
        Some(_) => Err("usage: eguard-agent pair [CODE] [--name NAME] | status".into()),
    };
    if let Err(e) = result {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
