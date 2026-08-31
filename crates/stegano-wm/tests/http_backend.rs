//! SEC-WM2: the local HTTP backend, end-to-end against a one-shot in-process
//! mock server. No real network, no real Ollama. The mock reads the COMPLETE
//! request (headers plus the Content-Length body) before answering, so there is
//! no race between the client's write and the server's response.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use stegano_wm::{InferenceBackend, Locality, HttpBackend};

/// Read one full HTTP request from `stream`: headers, then Content-Length bytes.
fn read_full_request(stream: &mut std::net::TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let mut data = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                data.extend_from_slice(&buf[..n]);
                if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&data[..pos]).to_lowercase();
                    let content_length = head.lines().find_map(|line| {
                        line.strip_prefix("content-length:")
                            .and_then(|v| v.trim().parse::<usize>().ok())
                    });
                    let body_len = data.len() - (pos + 4);
                    match content_length {
                        Some(cl) if body_len >= cl => break,
                        None => break,
                        _ => {}
                    }
                }
            }
            Err(_) => break,
        }
    }
}

/// A one-shot mock of an OpenAI-compatible server returning `content` (plain
/// ASCII, no JSON-special characters) as the completion.
fn spawn_mock(content: &'static str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            read_full_request(&mut stream);
            let body =
                format!("{{\"choices\":[{{\"message\":{{\"content\":\"{content}\"}}}}]}}");
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    port
}

#[test]
fn local_http_backend_parses_a_chat_completion() {
    let port = spawn_mock("We start the large effort to assist numerous folks.");
    let backend = HttpBackend::new(
        format!("http://127.0.0.1:{port}"),
        "test-model",
        "Rewrite the text.",
    )
    .with_timeout(Duration::from_secs(5));

    let out = backend
        .rewrite("We begin the big project to help many people.")
        .expect("the mock returns a valid completion");
    assert!(out.contains("large"));
    assert_eq!(backend.locality(), Locality::Local);
}

#[test]
fn an_unreachable_server_is_unavailable_not_a_panic() {
    let backend = HttpBackend::new("http://127.0.0.1:1", "m", "s")
        .with_timeout(Duration::from_millis(300));
    assert!(backend.rewrite("hello").is_err());
}
