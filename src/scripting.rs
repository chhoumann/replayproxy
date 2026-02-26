use std::collections::BTreeMap;

use anyhow::{Context, bail};
use hyper::{
    Method, Uri,
    header::{HeaderName, HeaderValue},
};
use mlua::{Function, Lua, String as LuaString, Table, Value};

pub const TRANSFORM_FUNCTION_NAME: &str = "transform";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptRequest {
    pub method: String,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl ScriptRequest {
    pub fn new(
        method: impl Into<String>,
        url: impl Into<String>,
        headers: BTreeMap<String, String>,
        body: Vec<u8>,
    ) -> Self {
        Self {
            method: method.into(),
            url: url.into(),
            headers,
            body,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl ScriptResponse {
    pub fn new(status: u16, headers: BTreeMap<String, String>, body: Vec<u8>) -> Self {
        Self {
            status,
            headers,
            body,
        }
    }
}

pub fn run_on_request_script(
    route_ref: &str,
    script_label: &str,
    script_source: &str,
    request: &mut ScriptRequest,
) -> anyhow::Result<()> {
    let transformed = run_message_script(
        route_ref,
        "on_request",
        "request",
        script_label,
        script_source,
        request,
        request_to_lua_table,
        request_from_lua_table,
    )?;
    *request = transformed;
    Ok(())
}

pub fn run_on_response_script(
    route_ref: &str,
    script_label: &str,
    script_source: &str,
    response: &mut ScriptResponse,
) -> anyhow::Result<()> {
    let transformed = run_message_script(
        route_ref,
        "on_response",
        "response",
        script_label,
        script_source,
        response,
        response_to_lua_table,
        response_from_lua_table,
    )?;
    *response = transformed;
    Ok(())
}

fn run_message_script<T>(
    route_ref: &str,
    hook_name: &str,
    global_name: &str,
    script_label: &str,
    script_source: &str,
    message: &T,
    to_lua_table: fn(&Lua, &T) -> mlua::Result<Table>,
    from_lua_table: fn(Table) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let lua = Lua::new();
    let globals = lua.globals();
    let message_table = to_lua_table(&lua, message).map_err(|err| {
        script_context_error(
            route_ref,
            hook_name,
            script_label,
            "prepare script input",
            err,
        )
    })?;
    globals
        .set(global_name, message_table.clone())
        .map_err(|err| {
            script_context_error(route_ref, hook_name, script_label, "set globals", err)
        })?;

    lua.load(script_source)
        .set_name(script_label)
        .exec()
        .map_err(|err| script_context_error(route_ref, hook_name, script_label, "execute", err))?;

    let transform_fn: Option<Function> = globals.get(TRANSFORM_FUNCTION_NAME).map_err(|err| {
        script_context_error(route_ref, hook_name, script_label, "load transform()", err)
    })?;
    if let Some(transform_fn) = transform_fn {
        let result: Value = transform_fn.call(message_table).map_err(|err| {
            script_context_error(route_ref, hook_name, script_label, "call transform()", err)
        })?;
        match result {
            Value::Nil => {}
            Value::Table(table) => {
                globals.set(global_name, table).map_err(|err| {
                    script_context_error(
                        route_ref,
                        hook_name,
                        script_label,
                        "apply transform() result",
                        err,
                    )
                })?;
            }
            _ => {
                bail!(
                    "lua `{hook_name}` script failed for route `{route_ref}` in `{script_label}`: `{TRANSFORM_FUNCTION_NAME}` must return a table or nil"
                );
            }
        }
    }

    let transformed_table: Table = globals.get(global_name).map_err(|err| {
        script_context_error(
            route_ref,
            hook_name,
            script_label,
            "read transformed value",
            err,
        )
    })?;
    from_lua_table(transformed_table).map_err(|err| {
        script_context_error(
            route_ref,
            hook_name,
            script_label,
            "decode transformed value",
            err,
        )
    })
}

fn request_to_lua_table(lua: &Lua, request: &ScriptRequest) -> mlua::Result<Table> {
    let table = lua.create_table()?;
    table.set("method", request.method.as_str())?;
    table.set("url", request.url.as_str())?;
    table.set("headers", headers_to_lua_table(lua, &request.headers)?)?;
    table.set("body", lua.create_string(&request.body)?)?;
    Ok(table)
}

fn response_to_lua_table(lua: &Lua, response: &ScriptResponse) -> mlua::Result<Table> {
    let table = lua.create_table()?;
    table.set("status", response.status)?;
    table.set("headers", headers_to_lua_table(lua, &response.headers)?)?;
    table.set("body", lua.create_string(&response.body)?)?;
    Ok(table)
}

fn request_from_lua_table(table: Table) -> anyhow::Result<ScriptRequest> {
    let method: String = table
        .get("method")
        .map_err(|err| anyhow::anyhow!("`request.method` must be present and a string: {err}"))?;
    if method.trim().is_empty() {
        bail!("`request.method` must not be empty");
    }
    Method::from_bytes(method.as_bytes())
        .with_context(|| format!("`request.method` is not a valid HTTP method: `{method}`"))?;

    let url: String = table
        .get("url")
        .map_err(|err| anyhow::anyhow!("`request.url` must be present and a string: {err}"))?;
    if url.trim().is_empty() {
        bail!("`request.url` must not be empty");
    }
    let _: Uri = url
        .parse()
        .with_context(|| format!("`request.url` is not a valid URI: `{url}`"))?;

    let headers = headers_from_lua_table(
        table
            .get("headers")
            .map_err(|err| anyhow::anyhow!("load `request.headers`: {err}"))?,
    )?;
    let body = body_from_lua_table(&table, "body")?;

    Ok(ScriptRequest {
        method,
        url,
        headers,
        body,
    })
}

fn response_from_lua_table(table: Table) -> anyhow::Result<ScriptResponse> {
    let status: u16 = table.get("status").map_err(|err| {
        anyhow::anyhow!("`response.status` must be present and an integer: {err}")
    })?;
    hyper::StatusCode::from_u16(status)
        .with_context(|| format!("`response.status` must be a valid HTTP status code: {status}"))?;

    let headers = headers_from_lua_table(
        table
            .get("headers")
            .map_err(|err| anyhow::anyhow!("load `response.headers`: {err}"))?,
    )?;
    let body = body_from_lua_table(&table, "body")?;

    Ok(ScriptResponse {
        status,
        headers,
        body,
    })
}

fn headers_to_lua_table(lua: &Lua, headers: &BTreeMap<String, String>) -> mlua::Result<Table> {
    let table = lua.create_table()?;
    for (name, value) in headers {
        table.set(name.as_str(), value.as_str())?;
    }
    Ok(table)
}

fn headers_from_lua_table(
    headers_table: Option<Table>,
) -> anyhow::Result<BTreeMap<String, String>> {
    let Some(headers_table) = headers_table else {
        return Ok(BTreeMap::new());
    };
    let mut headers = BTreeMap::new();
    for pair in headers_table.pairs::<String, Value>() {
        let (name, value) = pair.map_err(|err| anyhow::anyhow!("iterate headers table: {err}"))?;
        if name.trim().is_empty() {
            bail!("header names in script output must not be empty");
        }
        HeaderName::from_bytes(name.as_bytes())
            .with_context(|| format!("header name `{name}` is invalid"))?;

        let value = match value {
            Value::String(value) => lua_string_to_utf8(&value)
                .with_context(|| format!("header `{name}` must contain valid UTF-8 text"))?,
            _ => bail!("header `{name}` must be a string"),
        };
        HeaderValue::from_str(&value)
            .with_context(|| format!("header `{name}` has an invalid value"))?;
        headers.insert(name, value);
    }
    Ok(headers)
}

fn body_from_lua_table(table: &Table, field_name: &str) -> anyhow::Result<Vec<u8>> {
    let body: Option<LuaString> = table
        .get(field_name)
        .map_err(|err| anyhow::anyhow!("`{field_name}` must be a string when present: {err}"))?;
    let Some(body) = body else {
        return Ok(Vec::new());
    };
    Ok(body.as_bytes().as_ref().to_vec())
}

fn lua_string_to_utf8(value: &LuaString) -> anyhow::Result<String> {
    let bytes = value.as_bytes();
    let utf8 = std::str::from_utf8(bytes.as_ref()).context("string is not valid UTF-8")?;
    Ok(utf8.to_owned())
}

fn script_context_error(
    route_ref: &str,
    hook_name: &str,
    script_label: &str,
    stage: &str,
    source: impl std::fmt::Display,
) -> anyhow::Error {
    anyhow::anyhow!(
        "lua `{hook_name}` script failed for route `{route_ref}` in `{script_label}` while {stage}: {source}"
    )
}

#[cfg(test)]
mod tests {
    use super::{ScriptRequest, ScriptResponse, run_on_request_script, run_on_response_script};
    use std::collections::BTreeMap;

    fn headers(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect()
    }

    #[test]
    fn request_script_can_mutate_method_url_headers_and_body() {
        let mut request = ScriptRequest::new(
            "GET",
            "/v1/messages",
            headers(&[("x-initial", "one")]),
            b"body".to_vec(),
        );
        let script = r#"
request.method = "POST"
request.url = request.url .. "?stream=true"
request.headers["authorization"] = "Bearer token"
request.body = request.body .. "::rewritten"
"#;

        run_on_request_script(
            "routes[0] (anthropic)",
            "scripts/auth.lua",
            script,
            &mut request,
        )
        .unwrap();

        assert_eq!(request.method, "POST");
        assert_eq!(request.url, "/v1/messages?stream=true");
        assert_eq!(
            request.headers.get("authorization"),
            Some(&"Bearer token".to_string())
        );
        assert_eq!(request.body, b"body::rewritten");
    }

    #[test]
    fn response_script_can_mutate_status_headers_and_body() {
        let mut response = ScriptResponse::new(
            200,
            headers(&[("content-type", "text/plain")]),
            b"ok".to_vec(),
        );
        let script = r#"
function transform(response)
  response.status = 202
  response.headers["x-cache"] = "hit"
  response.body = response.body .. "::patched"
  return response
end
"#;

        run_on_response_script(
            "routes[1] (chat)",
            "scripts/response.lua",
            script,
            &mut response,
        )
        .unwrap();

        assert_eq!(response.status, 202);
        assert_eq!(response.headers.get("x-cache"), Some(&"hit".to_string()));
        assert_eq!(response.body, b"ok::patched");
    }

    #[test]
    fn script_errors_include_route_and_hook_context() {
        let mut request = ScriptRequest::new("GET", "/v1", BTreeMap::new(), Vec::new());
        let err = run_on_request_script(
            "routes[2] (openai)",
            "scripts/request.lua",
            "error('boom')",
            &mut request,
        )
        .unwrap_err();
        let message = err.to_string();

        assert!(message.contains("on_request"), "err: {message}");
        assert!(message.contains("routes[2] (openai)"), "err: {message}");
        assert!(message.contains("scripts/request.lua"), "err: {message}");
        assert!(message.contains("boom"), "err: {message}");
    }
}
