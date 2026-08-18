use std::process::{Command, Child};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tauri::RunEvent;

fn main() {
    let child_arc: Arc<Mutex<Option<Child>>> = Arc::new(Mutex::new(None));
    let child_clone = Arc::clone(&child_arc);

    // Spawn the backend server on 127.0.0.1
    thread::spawn(move || {
        let mut attempts = 0;
        let max_attempts = 10;
        let mut spawned = false;

        while attempts < max_attempts && !spawned {
            // Locate the server bundle
            let paths_to_try = vec![
                "dist/server.cjs",
                "../dist/server.cjs",
                "server.ts",
                "../server.ts",
            ];

            for path in paths_to_try {
                if std::path::Path::new(path).exists() {
                    let mut cmd;
                    if path.ends_with(".ts") {
                        cmd = Command::new("npx");
                        cmd.arg("tsx");
                        cmd.arg(path);
                    } else {
                        cmd = Command::new("node");
                        cmd.arg(path);
                    }
                    cmd.env("PORT", "3000");
                    cmd.env("NODE_ENV", "production");

                    match cmd.spawn() {
                        Ok(child) => {
                            let mut lock = child_clone.lock().unwrap();
                            *lock = Some(child);
                            spawned = true;
                            break;
                        }
                        Err(e) => {
                            eprintln!("Failed to spawn backend process for {}: {}", path, e);
                        }
                    }
                }
            }

            if !spawned {
                thread::sleep(Duration::from_millis(500));
                attempts += 1;
            }
        }

        if spawned {
            // Wait/poll for backend to be ready on 127.0.0.1:3000 via TCP connection check
            for _ in 0..50 {
                if std::net::TcpStream::connect("127.0.0.1:3000").is_ok() {
                    println!("Backend process successfully initialized on 127.0.0.1:3000");
                    break;
                }
                thread::sleep(Duration::from_millis(200));
            }
        }
    });

    tauri::Builder::default()
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(move |_app_handle, event| match event {
            RunEvent::Exit => {
                let mut lock = child_arc.lock().unwrap();
                if let Some(mut child) = lock.take() {
                    let _ = child.kill();
                    println!("Terminated backend process on application exit.");
                }
            }
            _ => {}
        });
}
