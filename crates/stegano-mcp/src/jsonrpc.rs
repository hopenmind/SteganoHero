//! JSON-RPC 2.0 envelope, written directly against the specification.
//!
//! No client library is involved. A message is a single line of JSON; a
//! request carries an identifier and is answered, a notification carries none
//! and is not. Errors use the codes the specification reserves, and every one
//! of them carries a reason a caller can act on.

use serde_json::{json, Value};

/// The JSON received could not be parsed.
pub const PARSE_ERROR: i64 = -32700;
/// The JSON parsed but is not a valid request object.
pub const INVALID_REQUEST: i64 = -32600;
/// The requested method does not exist.
pub const METHOD_NOT_FOUND: i64 = -32601;
/// The method exists but the parameters are not usable.
pub const INVALID_PARAMS: i64 = -32602;
/// The method failed for a reason internal to this surface.
pub const INTERNAL_ERROR: i64 = -32603;

/// A parsed incoming message.
#[derive(Debug, Clone)]
pub struct Incoming {
    /// Present on a request, absent on a notification.
    pub id: Option<Value>,
    pub method: String,
    pub params: Value,
}

/// Why an incoming line could not be turned into a message.
#[derive(Debug, Clone)]
pub struct Malformed {
    pub code: i64,
    pub message: String,
    /// The identifier, when the line carried a usable one.
    pub id: Option<Value>,
}

/// Parse one line into a message.
pub fn parse(line: &str) -> Result<Incoming, Malformed> {
    let value: Value = serde_json::from_str(line).map_err(|e| Malformed {
        code: PARSE_ERROR,
        message: format!("the line is not valid JSON: {e}"),
        id: None,
    })?;

    if value.is_array() {
        return Err(Malformed {
            code: INVALID_REQUEST,
            message: "batched requests are not accepted: send one message per line".into(),
            id: None,
        });
    }

    let object = value.as_object().ok_or_else(|| Malformed {
        code: INVALID_REQUEST,
        message: "a message must be a JSON object".into(),
        id: None,
    })?;

    // An identifier of null is not an identifier: the specification allows
    // only a string or a number, so a null one is treated as absent.
    let id = match object.get("id") {
        Some(Value::Null) | None => None,
        Some(Value::String(text)) => Some(Value::String(text.clone())),
        Some(Value::Number(number)) => Some(Value::Number(number.clone())),
        Some(other) => {
            return Err(Malformed {
                code: INVALID_REQUEST,
                message: format!(
                    "the request identifier must be a string or a number, received {}",
                    kind_of(other)
                ),
                id: None,
            })
        }
    };

    match object.get("jsonrpc") {
        Some(Value::String(version)) if version == "2.0" => {}
        Some(other) => {
            return Err(Malformed {
                code: INVALID_REQUEST,
                message: format!("unsupported protocol envelope: expected \"2.0\", received {other}"),
                id,
            })
        }
        None => {
            return Err(Malformed {
                code: INVALID_REQUEST,
                message: "the message carries no protocol envelope field".into(),
                id,
            })
        }
    }

    let method = match object.get("method") {
        Some(Value::String(name)) => name.clone(),
        Some(other) => {
            return Err(Malformed {
                code: INVALID_REQUEST,
                message: format!("the method name must be a string, received {}", kind_of(other)),
                id,
            })
        }
        None => {
            return Err(Malformed {
                code: INVALID_REQUEST,
                message: "the message names no method".into(),
                id,
            })
        }
    };

    let params = match object.get("params") {
        None | Some(Value::Null) => json!({}),
        Some(value @ Value::Object(_)) => value.clone(),
        Some(other) => {
            return Err(Malformed {
                code: INVALID_PARAMS,
                message: format!("parameters must be an object, received {}", kind_of(other)),
                id,
            })
        }
    };

    Ok(Incoming { id, method, params })
}

/// Build a successful response.
pub fn success(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

/// Build an error response.
pub fn failure(id: Option<Value>, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id.unwrap_or(Value::Null),
        "error": { "code": code, "message": message },
    })
}

/// Build an error response carrying structured detail alongside the reason.
pub fn failure_with_data(id: Option<Value>, code: i64, message: &str, data: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id.unwrap_or(Value::Null),
        "error": { "code": code, "message": message, "data": data },
    })
}

fn kind_of(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_parses_with_its_identifier() {
        let parsed = parse(r#"{"jsonrpc":"2.0","id":7,"method":"tools/list"}"#).expect("must parse");
        assert_eq!(parsed.id, Some(json!(7)));
        assert_eq!(parsed.method, "tools/list");
        assert_eq!(parsed.params, json!({}));
    }

    #[test]
    fn a_notification_parses_without_an_identifier() {
        let parsed =
            parse(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#).expect("must parse");
        assert!(parsed.id.is_none());
    }

    #[test]
    fn a_null_identifier_is_read_as_absent() {
        let parsed = parse(r#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#).expect("must parse");
        assert!(parsed.id.is_none());
    }

    #[test]
    fn broken_json_is_refused_with_the_reserved_code() {
        let error = parse("{not json").expect_err("must be refused");
        assert_eq!(error.code, PARSE_ERROR);
    }

    #[test]
    fn a_batch_is_refused_by_name() {
        let error = parse(r#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#).expect_err("must be refused");
        assert_eq!(error.code, INVALID_REQUEST);
        assert!(error.message.contains("one message per line"));
    }

    #[test]
    fn a_missing_envelope_is_refused() {
        let error = parse(r#"{"id":1,"method":"ping"}"#).expect_err("must be refused");
        assert_eq!(error.code, INVALID_REQUEST);
    }

    #[test]
    fn a_wrong_envelope_version_is_refused_and_keeps_the_identifier() {
        let error = parse(r#"{"jsonrpc":"1.0","id":3,"method":"ping"}"#).expect_err("must be refused");
        assert_eq!(error.code, INVALID_REQUEST);
        assert_eq!(error.id, Some(json!(3)));
    }

    #[test]
    fn non_object_parameters_are_refused() {
        let error =
            parse(r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":[1,2]}"#).expect_err("must be refused");
        assert_eq!(error.code, INVALID_PARAMS);
    }

    #[test]
    fn a_failure_without_an_identifier_answers_with_null() {
        let response = failure(None, INTERNAL_ERROR, "reason");
        assert_eq!(response["id"], Value::Null);
        assert_eq!(response["error"]["code"], json!(INTERNAL_ERROR));
    }
}
