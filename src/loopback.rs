//! The loopback redirect for desktop sign-in (RFC 8252 §7.3): a one-shot
//! listener on `127.0.0.1` at a free port, which takes the browser's
//! redirect and answers with a page saying the app has it.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::Error;

/// The loopback redirect path Meros desktop clients are registered with.
pub const CALLBACK_PATH: &str = "/callback";

/// A listener waiting for one sign-in redirect.
pub struct LoopbackRedirect {
    listener: TcpListener,
    path: String,
    redirect_uri: String,
}

impl LoopbackRedirect {
    /// Listens on `127.0.0.1` at a free port for redirects to
    /// [`CALLBACK_PATH`], the path the Meros desktop clients are registered
    /// with (`http://127.0.0.1/callback`, any port).
    pub async fn bind() -> Result<LoopbackRedirect, Error> {
        Self::bind_path(CALLBACK_PATH).await
    }

    /// Like [`bind`](Self::bind), for an issuer registered with another path.
    pub async fn bind_path(path: &str) -> Result<LoopbackRedirect, Error> {
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|e| {
            Error::new(
                None,
                "loopback",
                format!("Could not listen for sign-in: {e}"),
            )
        })?;
        let port = listener
            .local_addr()
            .map_err(|e| Error::new(None, "loopback", e.to_string()))?
            .port();
        let path = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{path}")
        };
        Ok(LoopbackRedirect {
            redirect_uri: format!("http://127.0.0.1:{port}{path}"),
            listener,
            path,
        })
    }

    /// The redirect to hand to
    /// [`MerosAuth::begin_sign_in_with`](crate::MerosAuth::begin_sign_in_with).
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    /// Waits for the browser's redirect and returns its full URL, for
    /// [`MerosAuth::complete_sign_in`](crate::MerosAuth::complete_sign_in).
    /// Requests to other paths (a favicon) are answered 404 and ignored.
    /// `timeout` ends the wait with the code `timeout`.
    pub async fn wait(self, timeout: Duration) -> Result<String, Error> {
        tokio::time::timeout(timeout, self.accept())
            .await
            .map_err(|_| Error::new(None, "timeout", "Sign-in took too long. Try again."))?
    }

    async fn accept(&self) -> Result<String, Error> {
        loop {
            let (mut socket, _) = self
                .listener
                .accept()
                .await
                .map_err(|e| Error::new(None, "loopback", e.to_string()))?;
            let mut buf = Vec::new();
            let mut chunk = [0u8; 2048];
            while !buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() < 16 * 1024 {
                match socket.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
            }
            let head = String::from_utf8_lossy(&buf);
            let target = head
                .lines()
                .next()
                .and_then(|l| l.strip_prefix("GET "))
                .and_then(|l| l.split(' ').next())
                .unwrap_or("");
            let (path, _) = target.split_once('?').unwrap_or((target, ""));
            if path != self.path {
                let _ = socket
                    .write_all(
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
                continue;
            }
            let page = "<!doctype html><meta charset=utf-8><title>Signed in</title>\
                <body style=\"font-family:sans-serif;text-align:center;padding-top:4em\">\
                <p>You can close this window and return to the app.</p>";
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{page}",
                page.len()
            );
            let _ = socket.write_all(reply.as_bytes()).await;
            let origin = self.redirect_uri.trim_end_matches(&self.path);
            return Ok(format!("{origin}{target}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpStream;

    async fn get(addr: &str, target: &str) -> String {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(format!("GET {target} HTTP/1.1\r\nHost: {addr}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        out
    }

    #[tokio::test]
    async fn takes_the_redirect_and_ignores_other_paths() {
        let lb = LoopbackRedirect::bind().await.unwrap();
        let uri = lb.redirect_uri().to_string();
        assert!(uri.starts_with("http://127.0.0.1:") && uri.ends_with("/callback"));
        let addr = uri
            .trim_start_matches("http://")
            .trim_end_matches("/callback")
            .to_string();
        let waiting = tokio::spawn(lb.wait(Duration::from_secs(5)));
        assert!(get(&addr, "/favicon.ico").await.starts_with("HTTP/1.1 404"));
        assert!(
            get(&addr, "/callback?code=c1&state=s1")
                .await
                .contains("close this window")
        );
        assert_eq!(
            waiting.await.unwrap().unwrap(),
            format!("{uri}?code=c1&state=s1")
        );
    }

    #[tokio::test]
    async fn gives_up_after_the_timeout() {
        let lb = LoopbackRedirect::bind_path("cb").await.unwrap();
        let e = lb.wait(Duration::from_millis(50)).await.unwrap_err();
        assert_eq!(e.code, "timeout");
    }
}
