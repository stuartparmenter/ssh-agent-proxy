use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use std::sync::Arc;

use crate::agent_source::AgentSource;
use crate::config;

const MAX_BODY: usize = 16 << 20; // 16 MiB

pub struct AppState {
    pub source: AgentSource,
    pub namespace: String,
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/sign", post(sign_handler))
        .route("/publickey", get(publickey_handler))
        .route("/healthz", get(healthz_handler))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(state)
}

async fn sign_handler(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    if body.is_empty() {
        return (StatusCode::BAD_REQUEST, "empty request body\n").into_response();
    }
    if body.len() > MAX_BODY {
        return (StatusCode::BAD_REQUEST, "request body too large\n").into_response();
    }

    let signer = match state.source.signer() {
        Ok(s) => s,
        Err(e) => {
            log::error!("signer fetch: {e}");
            return (StatusCode::SERVICE_UNAVAILABLE, "signer unavailable\n").into_response();
        }
    };

    match crate::sshsig::sign(signer.as_ref(), &state.namespace, &body) {
        Ok(sig) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/x-ssh-signature")],
            sig,
        )
            .into_response(),
        Err(e) => {
            log::error!("sign error: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "sign failed\n").into_response()
        }
    }
}

async fn publickey_handler(State(state): State<Arc<AppState>>) -> Response {
    let signer = match state.source.signer() {
        Ok(s) => s,
        Err(e) => {
            log::error!("signer fetch: {e}");
            return (StatusCode::SERVICE_UNAVAILABLE, "signer unavailable\n").into_response();
        }
    };

    match config::marshal_authorized_key(&signer.public_key().wire) {
        Ok(line) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
                (header::CACHE_CONTROL, "no-cache"),
            ],
            line,
        )
            .into_response(),
        Err(e) => {
            log::error!("marshal key: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "key format error\n").into_response()
        }
    }
}

async fn healthz_handler() -> &'static str {
    "ok\n"
}
