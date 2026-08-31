//! The channel: one JSON message per line, in on standard input, out on
//! standard output.
//!
//! Standard output carries protocol messages and nothing else, so anything
//! worth saying to an operator goes to standard error. What goes there is a
//! method name and an outcome. Arguments are never written anywhere: they are
//! where secrets and passcodes live.

use std::io::{BufRead, Write};

use serde_json::{json, Value};

use crate::jsonrpc::{self, Malformed};
use crate::tools::{self, Outcome, SettingsStore};

/// What a handled line produced.
pub struct Handled {
    /// The line to write back, or nothing when the message was a notification.
    pub response: Option<String>,
    /// One short line for the operator. Never carries any argument value.
    pub log: String,
}

/// Handle one incoming line.
pub fn handle_line(line: &str, store: &mut SettingsStore) -> Handled {
    let incoming = match jsonrpc::parse(line) {
        Ok(incoming) => incoming,
        Err(Malformed { code, message, id }) => {
            // A malformed notification still gets no reply: without an
            // identifier there is nothing to reply to.
            let log = format!("malformed message refused, code {code}");
            return Handled {
                response: Some(render(jsonrpc::failure(id, code, &message))),
                log,
            };
        }
    };

    let is_notification = incoming.id.is_none();
    let method = incoming.method.clone();

    let outcome = dispatch(&incoming.method, &incoming.params, store);

    let log = match &outcome {
        Dispatched::Result(_) => format!("{method}: answered"),
        Dispatched::Error { code, .. } => format!("{method}: refused, code {code}"),
        Dispatched::Silent => format!("{method}: noted"),
    };

    let response = match (is_notification, outcome) {
        (true, _) => None,
        (false, Dispatched::Silent) => Some(render(jsonrpc::success(
            incoming.id.unwrap_or(Value::Null),
            json!({}),
        ))),
        (false, Dispatched::Result(value)) => Some(render(jsonrpc::success(
            incoming.id.unwrap_or(Value::Null),
            value,
        ))),
        (false, Dispatched::Error { code, message, data }) => Some(render(match data {
            Some(data) => jsonrpc::failure_with_data(incoming.id, code, &message, data),
            None => jsonrpc::failure(incoming.id, code, &message),
        })),
    };

    Handled { response, log }
}

enum Dispatched {
    Result(Value),
    Error {
        code: i64,
        message: String,
        data: Option<Value>,
    },
    /// Handled, with nothing to report.
    Silent,
}

fn dispatch(method: &str, params: &Value, store: &mut SettingsStore) -> Dispatched {
    match method {
        "initialize" => Dispatched::Result(initialize(params)),
        "ping" => Dispatched::Result(json!({})),
        "tools/list" => Dispatched::Result(json!({ "tools": tools::tool_list_payload() })),
        "tools/call" => call_tool(params, store),
        other if other.starts_with("notifications/") => Dispatched::Silent,
        other => Dispatched::Error {
            code: jsonrpc::METHOD_NOT_FOUND,
            message: format!("unsupported method '{other}'"),
            data: None,
        },
    }
}

fn initialize(params: &Value) -> Value {
    // Answer in the version the client asked for when it is one this surface
    // speaks; otherwise answer in the version it does speak and let the client
    // decide. Nothing is assumed on the client's behalf.
    let requested = params
        .get("protocolVersion")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let version = if crate::SUPPORTED_PROTOCOL_VERSIONS.contains(&requested) {
        requested
    } else {
        crate::PROTOCOL_VERSION
    };

    json!({
        "protocolVersion": version,
        "capabilities": { "tools": { "listChanged": false } },
        "serverInfo": {
            "name": crate::SERVER_NAME,
            "title": "SteganoHero",
            "version": crate::SERVER_VERSION,
        },
        "instructions": "Start with capabilities_list to see what is available, then capacity_report on the document you intend to work with. Capacity depends on the document, so a plan that works on one text may be refused on another. Every command refuses with a reason rather than returning a result it could not confirm.",
    })
}

fn call_tool(params: &Value, store: &mut SettingsStore) -> Dispatched {
    let name = match params.get("name") {
        Some(Value::String(name)) => name.clone(),
        Some(_) => {
            return Dispatched::Error {
                code: jsonrpc::INVALID_PARAMS,
                message: "'name' must be a string".into(),
                data: None,
            }
        }
        None => {
            return Dispatched::Error {
                code: jsonrpc::INVALID_PARAMS,
                message: "'name' is required: it selects which command to run".into(),
                data: None,
            }
        }
    };

    let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

    match tools::call(&name, &arguments, store) {
        Outcome::Done(value) => Dispatched::Result(tool_result(value, None)),
        Outcome::Refused { code, reason } => Dispatched::Result(tool_result(
            json!({ "error": { "code": code, "reason": reason } }),
            Some(format!("{code}: {reason}")),
        )),
        Outcome::BadArguments(reason) => Dispatched::Error {
            code: jsonrpc::INVALID_PARAMS,
            message: reason,
            data: Some(json!({ "tool": name })),
        },
        Outcome::Unknown(reason) => Dispatched::Error {
            code: jsonrpc::METHOD_NOT_FOUND,
            message: reason,
            data: None,
        },
    }
}

/// Build the payload a command call answers with.
///
/// A refusal comes back as a result carrying its reason, not as a protocol
/// error, so the caller sees why and can act on it. A protocol error is
/// reserved for a message this surface could not make sense of at all.
fn tool_result(structured: Value, failure: Option<String>) -> Value {
    let text = match &failure {
        Some(reason) => reason.clone(),
        None => serde_json::to_string_pretty(&structured)
            .unwrap_or_else(|_| structured.to_string()),
    };
    json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": structured,
        "isError": failure.is_some(),
    })
}

fn render(value: Value) -> String {
    // One message per line: a response is compact JSON with no newline in it.
    value.to_string()
}

/// Run the channel until the input closes.
pub fn serve(
    input: impl BufRead,
    mut output: impl Write,
    mut errors: impl Write,
    store: &mut SettingsStore,
) -> std::io::Result<()> {
    for line in input.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let handled = handle_line(&line, store);
        let _ = writeln!(errors, "{}", handled.log);
        if let Some(response) = handled.response {
            writeln!(output, "{response}")?;
            output.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::Settings;

    fn store() -> SettingsStore {
        SettingsStore::in_memory(Settings::default())
    }

    fn answer(line: &str) -> Value {
        let handled = handle_line(line, &mut store());
        serde_json::from_str(&handled.response.expect("a request must be answered"))
            .expect("the answer must be JSON")
    }

    #[test]
    fn initialize_answers_with_the_requested_version_when_it_is_supported() {
        let response = answer(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}"#,
        );
        assert_eq!(response["result"]["protocolVersion"], json!("2024-11-05"));
        assert_eq!(response["result"]["serverInfo"]["name"], json!(crate::SERVER_NAME));
        assert_eq!(
            response["result"]["capabilities"]["tools"]["listChanged"],
            json!(false)
        );
    }

    #[test]
    fn initialize_answers_with_its_own_version_when_the_request_names_another() {
        let response = answer(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}"#,
        );
        assert_eq!(
            response["result"]["protocolVersion"],
            json!(crate::PROTOCOL_VERSION)
        );
    }

    #[test]
    fn a_notification_is_not_answered() {
        let handled = handle_line(
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            &mut store(),
        );
        assert!(handled.response.is_none());
    }

    #[test]
    fn the_command_list_carries_a_schema_for_every_command() {
        let response = answer(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#);
        let listed = response["result"]["tools"].as_array().expect("an array");
        assert_eq!(listed.len(), tools::tool_names().len());
        for tool in listed {
            assert!(tool["name"].is_string());
            assert!(tool["description"].is_string());
            assert_eq!(tool["inputSchema"]["type"], json!("object"));
        }
    }

    #[test]
    fn a_command_call_answers_with_content_and_structure() {
        let response = answer(
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"capabilities_list","arguments":{}}}"#,
        );
        assert_eq!(response["result"]["isError"], json!(false));
        assert_eq!(response["result"]["content"][0]["type"], json!("text"));
        assert!(response["result"]["structuredContent"]["carriers"].is_array());
    }

    #[test]
    fn a_refusal_comes_back_as_a_result_carrying_its_reason() {
        let response = answer(
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"chain_validate","arguments":{"carriers":["homoglyph","bidi"],"preserve_order":true}}}"#,
        );
        assert_eq!(response["result"]["isError"], json!(true));
        assert_eq!(
            response["result"]["structuredContent"]["error"]["code"],
            json!("composition_refused")
        );
    }

    #[test]
    fn an_unknown_command_is_a_protocol_error() {
        let response = answer(
            r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"nope","arguments":{}}}"#,
        );
        assert_eq!(response["error"]["code"], json!(jsonrpc::METHOD_NOT_FOUND));
    }

    #[test]
    fn unusable_arguments_are_a_protocol_error() {
        let response = answer(
            r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"analyze","arguments":{}}}"#,
        );
        assert_eq!(response["error"]["code"], json!(jsonrpc::INVALID_PARAMS));
        assert!(response["error"]["message"].as_str().unwrap().contains("text"));
    }

    #[test]
    fn an_unsupported_method_is_refused_with_the_reserved_code() {
        let response = answer(r#"{"jsonrpc":"2.0","id":7,"method":"resources/list"}"#);
        assert_eq!(response["error"]["code"], json!(jsonrpc::METHOD_NOT_FOUND));
    }

    #[test]
    fn ping_is_answered() {
        let response = answer(r#"{"jsonrpc":"2.0","id":8,"method":"ping"}"#);
        assert!(response["result"].is_object());
        assert!(response.get("error").is_none());
    }

    #[test]
    fn every_answer_is_a_single_line() {
        let handled = handle_line(r#"{"jsonrpc":"2.0","id":9,"method":"tools/list"}"#, &mut store());
        let response = handled.response.expect("must answer");
        assert!(!response.contains('\n'));
    }

    /// The operator log carries a method name and an outcome. It never carries
    /// an argument, because arguments are where secrets are.
    #[test]
    fn the_log_line_never_carries_an_argument() {
        let handled = handle_line(
            r#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"protect_payload","arguments":{"plaintext":"the secret text","cipher":"aes256_gcm","passcode":"the passcode"}}}"#,
            &mut store(),
        );
        assert!(!handled.log.contains("the secret text"));
        assert!(!handled.log.contains("the passcode"));
        assert!(!handled.log.contains("aes256_gcm"));
        assert_eq!(handled.log, "tools/call: answered");
    }

    #[test]
    fn a_broken_line_is_answered_without_an_identifier() {
        let response = answer("{ not json");
        assert_eq!(response["error"]["code"], json!(jsonrpc::PARSE_ERROR));
        assert_eq!(response["id"], Value::Null);
    }

    #[test]
    fn the_channel_answers_a_sequence_and_stops_when_the_input_closes() {
        let input = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
            "\n",
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n"
        );
        let mut output = Vec::new();
        let mut errors = Vec::new();
        serve(
            std::io::Cursor::new(input),
            &mut output,
            &mut errors,
            &mut store(),
        )
        .expect("the channel must run to the end of the input");

        let written = String::from_utf8(output).expect("output must be text");
        let lines: Vec<&str> = written.lines().collect();
        assert_eq!(lines.len(), 2, "one answer per request, none for the rest");
        for line in lines {
            let value: Value = serde_json::from_str(line).expect("each line must be JSON");
            assert_eq!(value["jsonrpc"], json!("2.0"));
        }
    }
}
