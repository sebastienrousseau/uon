use base64::{engine::general_purpose, Engine as _};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use std::env;
use std::ffi::CString;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;

const DEFAULT_BROKER_SOCKET: &str = "/run/uon/zsp.sock";
const DEFAULT_EXEC_GROUP: &str = "uon-exec";

#[derive(Deserialize)]
struct BrokerRequest {
    command: String,
}

#[derive(Serialize)]
struct BrokerResponse {
    exit_code: i32,
    stdout: String,
    stderr: String,
}

fn env_int(name: &str) -> Result<Option<u32>, String> {
    match env::var(name) {
        Ok(value) if !value.is_empty() => value
            .parse::<u32>()
            .map(Some)
            .map_err(|e| format!("Invalid {} value: {}", name, e)),
        _ => Ok(None),
    }
}

fn resolve_exec_uid() -> Result<u32, String> {
    Ok(env_int("UON_ZSP_TARGET_UID")?.unwrap_or_else(|| unsafe { libc::geteuid() }))
}

fn resolve_exec_gid() -> Result<u32, String> {
    if let Some(gid) = env_int("UON_ZSP_EXEC_GID")? {
        return Ok(gid);
    }

    let group = CString::new(DEFAULT_EXEC_GROUP).map_err(|e| e.to_string())?;
    let raw = unsafe { libc::getgrnam(group.as_ptr()) };
    if raw.is_null() {
        return Ok(unsafe { libc::getegid() });
    }
    Ok(unsafe { (*raw).gr_gid })
}

fn resolve_socket_uid() -> Result<u32, String> {
    if let Some(uid) = env_int("UON_ZSP_SOCKET_UID")? {
        Ok(uid)
    } else {
        resolve_exec_uid()
    }
}

fn resolve_socket_gid() -> Result<u32, String> {
    if let Some(gid) = env_int("UON_ZSP_SOCKET_GID")? {
        Ok(gid)
    } else {
        resolve_exec_gid()
    }
}

fn socket_path() -> String {
    env::var("UON_ZSP_SOCKET").unwrap_or_else(|_| DEFAULT_BROKER_SOCKET.to_string())
}

fn apply_socket_ownership(path: &Path, uid: u32, gid: u32) -> Result<(), String> {
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|e| format!("Invalid socket path: {}", e))?;
    let rc = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().to_string())
    }
}

fn prepare_socket(path: &Path) -> Result<UnixListener, String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create broker socket directory: {}", e))?;
    }

    if path.exists() {
        let metadata = fs::metadata(path)
            .map_err(|e| format!("Failed to stat broker socket path: {}", e))?;
        if metadata.file_type().is_socket() {
            fs::remove_file(path)
                .map_err(|e| format!("Failed to remove stale broker socket: {}", e))?;
        } else {
            return Err(format!(
                "Refusing to replace non-socket path: {}",
                path.display()
            ));
        }
    }

    let listener = UnixListener::bind(path)
        .map_err(|e| format!("Failed to bind broker socket {}: {}", path.display(), e))?;

    apply_socket_ownership(path, resolve_socket_uid()?, resolve_socket_gid()?)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o660))
        .map_err(|e| format!("Failed to set broker socket permissions: {}", e))?;

    Ok(listener)
}

fn configure_privilege_drop(command: &mut Command) -> Result<(), String> {
    let target_uid = resolve_exec_uid()?;
    let target_gid = resolve_exec_gid()?;
    let current_uid = unsafe { libc::geteuid() };
    let current_gid = unsafe { libc::getegid() };
    let is_root = current_uid == 0;

    unsafe {
        command.pre_exec(move || {
            if !is_root {
                if current_uid == target_uid && current_gid == target_gid {
                    return Ok(());
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "ZSP broker lacks privileges to change UID/GID",
                ));
            }

            let groups = [target_gid];
            if libc::setgroups(groups.len(), groups.as_ptr()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setgid(target_gid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setuid(target_uid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    Ok(())
}

fn run_command(command: &str) -> BrokerResponse {
    let mut process = if let Some(parts) = shlex::split(command) {
        let mut iter = parts.into_iter();
        match iter.next() {
            Some(program) => {
                let mut cmd = Command::new(program);
                cmd.args(iter);
                cmd
            },
            None => {
                let mut cmd = Command::new("/bin/sh");
                cmd.arg("-lc").arg(command);
                cmd
            },
        }
    } else {
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-lc").arg(command);
        cmd
    };

    process.stdout(Stdio::piped()).stderr(Stdio::piped());

    let output = match configure_privilege_drop(&mut process).and_then(|_| {
        process
            .output()
            .map_err(|e| format!("Failed to execute broker command: {}", e))
    }) {
        Ok(output) => output,
        Err(err) => {
            return BrokerResponse {
                exit_code: 1,
                stdout: String::new(),
                stderr: general_purpose::STANDARD.encode(err.as_bytes()),
            }
        },
    };

    BrokerResponse {
        exit_code: output.status.code().unwrap_or(1),
        stdout: general_purpose::STANDARD.encode(&output.stdout),
        stderr: general_purpose::STANDARD.encode(&output.stderr),
    }
}

fn write_response(mut stream: UnixStream, response: &BrokerResponse) -> Result<(), String> {
    let payload = serde_json::to_string(response)
        .map_err(|e| format!("Failed to encode broker response: {}", e))?;
    stream
        .write_all(payload.as_bytes())
        .and_then(|_| stream.write_all(b"\n"))
        .map_err(|e| format!("Failed to write broker response: {}", e))
}

fn handle_connection(stream: UnixStream) -> Result<(), String> {
    let mut reader = BufReader::new(
        stream
            .try_clone()
            .map_err(|e| format!("Failed to clone broker stream: {}", e))?,
    );
    let mut request_line = String::new();
    let bytes_read = reader
        .read_line(&mut request_line)
        .map_err(|e| format!("Failed to read broker request: {}", e))?;

    if bytes_read == 0 {
        return Ok(());
    }

    let response = match serde_json::from_str::<BrokerRequest>(request_line.trim_end()) {
        Ok(request) => run_command(&request.command),
        Err(err) => BrokerResponse {
            exit_code: 1,
            stdout: String::new(),
            stderr: general_purpose::STANDARD.encode(err.to_string().as_bytes()),
        },
    };

    write_response(stream, &response)
}

pub fn run_broker_forever() -> Result<(), String> {
    let path = socket_path();
    let path_ref = Path::new(&path);
    let listener = prepare_socket(path_ref)?;

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    let _ = handle_connection(stream);
                });
            },
            Err(err) => return Err(format!("Broker accept loop failed: {}", err)),
        }
    }

    Ok(())
}

#[pyfunction]
pub fn run_zsp_broker() -> PyResult<()> {
    run_broker_forever().map_err(PyRuntimeError::new_err)
}
