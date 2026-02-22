use pyo3::prelude::*;
use pyo3::exceptions::PyRuntimeError;
use std::sync::Arc;
use tokio::runtime::Runtime;
use russh::client::{Handler};
use russh::ChannelMsg;
use async_trait::async_trait;

struct ClientHandler;

#[async_trait]
impl Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh_keys::key::PublicKey,
    ) -> Result<bool, Self::Error> {
        // TOFU validation. Currently allows any host key.
        Ok(true)
    }
}

#[pyfunction]
pub fn execute_signed_rust(
    host: String,
    port: u16,
    username: String,
    wrapped_command: String,
) -> PyResult<(i32, String, String)> {
    let rt = Runtime::new().map_err(|e| PyRuntimeError::new_err(format!("Tokio runtime error: {}", e)))?;

    rt.block_on(async {
        let config = russh::client::Config::default();
        let config = Arc::new(config);

        let mut session = if host.starts_with("unix:") {
            #[cfg(unix)]
            {
                let path = host.strip_prefix("unix:").unwrap_or(&host);
                let stream = tokio::net::UnixStream::connect(path)
                    .await
                    .map_err(|e| PyRuntimeError::new_err(format!("UnixStream connect error: {}", e)))?;
                russh::client::connect_stream(config, stream, ClientHandler)
                    .await
                    .map_err(|e| PyRuntimeError::new_err(format!("SSH stream error: {}", e)))?
            }
            #[cfg(not(unix))]
            {
                return Err(PyRuntimeError::new_err("Unix sockets not supported on this platform".to_string()));
            }
        } else {
            russh::client::connect(config, (host.as_str(), port), ClientHandler)
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("SSH connect error: {}", e)))?
        };

        // Note: Real implementations will orchestrate `russh-keys` to negotiate agent keys.
        // We simulate basic or no-auth connection here for the ForceCommand execution context.
        let _ = session.authenticate_none(&username).await;

        let mut channel = match session.channel_open_session().await {
            Ok(c) => c,
            Err(e) => return Err(PyRuntimeError::new_err(format!("SSH channel error: {}", e))),
        };

        if let Err(e) = channel.exec(true, wrapped_command).await {
            return Err(PyRuntimeError::new_err(format!("SSH exec error: {}", e)));
        }

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_status = 0;

        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { ref data } => stdout.extend_from_slice(data),
                ChannelMsg::ExtendedData { ref data, ext } => {
                    if ext == 1 {
                        stderr.extend_from_slice(data);
                    }
                },
                ChannelMsg::ExitStatus { exit_status: s } => {
                    exit_status = s as i32;
                },
                _ => {}
            }
        }

        let out = String::from_utf8_lossy(&stdout).into_owned();
        let err = String::from_utf8_lossy(&stderr).into_owned();

        Ok((exit_status, out, err))
    })
}
