pub mod auth;

use std::net::{SocketAddr, SocketAddrV6};

use async_trait::async_trait;
use auth::SignatureVerifier;
use axum::{
    body::Bytes,
    extract::{FromRequest, FromRequestParts},
    http::{request::Parts, Request, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, RequestExt, Router, Server,
};

use bytes::BytesMut;
use ed25519::Signature;
use ed25519_dalek::PublicKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tower_http::trace::TraceLayer;

static OAUTH_URL: &str = "https://discord.com/api/oauth2/authorize?client_id=1025095624695226469&permissions=2147485696&scope=bot%20applications.commands";

struct HeaderSignatures {
    timestamp: String,
    signature: String,
}

#[async_trait]
impl<S> FromRequestParts<S> for HeaderSignatures
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(req: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let signature = req
            .headers
            .get("X-Signature-Ed25519")
            .and_then(|x| x.to_str().ok())
            .ok_or(StatusCode::UNAUTHORIZED)?
            .to_owned();

        let timestamp = req
            .headers
            .get("X-Signature-Timestamp")
            .and_then(|x| x.to_str().ok())
            .ok_or(StatusCode::UNAUTHORIZED)?
            .to_owned();

        Ok(HeaderSignatures {
            timestamp,
            signature,
        })
    }
}

struct ValidatedBody(Bytes);

#[async_trait]
impl<S, B> FromRequest<S, B> for ValidatedBody
where
    B: Send + 'static,
    Bytes: FromRequest<S, B>,
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request(req: Request<B>, state: &S) -> Result<Self, Self::Rejection> {
        let mut req = req;

        let signature_fields = req.extract_parts::<HeaderSignatures>().await?;

        let body = Bytes::from_request(req, state)
            .await
            .or(Err(StatusCode::UNAUTHORIZED))?;

        let mut sig_body = BytesMut::from(signature_fields.timestamp.as_bytes());
        sig_body.extend(body.clone());

        let verifier = SignatureVerifier::<PublicKey> {
            verifier: PublicKey::from_bytes(
                &hex::decode(auth::PUBLIC_KEY).expect("could not decode PUBLIC_KEY"),
            )
            .expect("could not create public key from PUBLIC_KEY"),
        };

        let signature_bytes =
            hex::decode(signature_fields.signature.as_bytes()).or(Err(StatusCode::UNAUTHORIZED))?;
        verifier
            .verify(
                &sig_body,
                &Signature::from_bytes(&signature_bytes).or(Err(StatusCode::UNAUTHORIZED))?,
            )
            .or(Err(StatusCode::UNAUTHORIZED))?;

        Ok(Self(body))
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let app = Router::new()
        .route("/", get(root))
        .route("/interactions", post(interactions))
        .layer(TraceLayer::new_for_http());
    let addr = SocketAddr::from("[::]:3000".parse::<SocketAddrV6>().unwrap());

    tracing::debug!("listening on {addr:?}");
    Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap()
}

#[tracing::instrument]
async fn root() -> &'static str {
    "hello, world!"
}

#[derive(Serialize)]
struct PingResponse {
    #[serde(rename = "type")]
    response_type: usize,
}

#[derive(Serialize)]
#[serde(untagged)]
enum InteractionResponse {
    Empty,
    Ping(PingResponse),
}

mod discord {}
mod interaction {
    enum ApplicationCommandType {
        ChatInput,
        User,
        Message,
    }

    enum InteractionType {
        Ping,
        ApplicationCommand,
        MessageComponent,
        ApplicationCommandAutocomplete,
        ModalSubmit,
    }

    use serde::Deserialize;
    use serde_json::Value;

    #[derive(Deserialize)]
    struct Request {
        #[serde(rename = "type")]
        message_type: i32,
        data: Option<String>,
    }

    struct CommandOption {
        name: String,
        command_type: ApplicationCommandType,
        value: Option<String>,
        options: Option<Vec<CommandOption>>,
        focused: Option<bool>,
    }

    struct ApplicationCommand {
        id: String,
        name: String,
        message_type: ApplicationCommandType,
        _resolved: Option<Value> 
        options: Option<Vec<CommandOption>>,
        guild_id: Option<String>,
        target_id: Option<String>,
    }

    enum CallbackType {
        Pong,
        ChannelMessageWithSource,
        DeferredChannelMessageWithSource,
        DeferredUpdateMessage,
        UpdateMessage,
        ApplicationCommandAutocompleteResult,
        Modal,
    }

    struct Response {
        callback_type: CallbackType,
    }
}

async fn interactions(ValidatedBody(body): ValidatedBody) -> impl IntoResponse {
    let payload = serde_json::from_slice::<Value>(&body[..]);
    if payload.is_err() {
        return (StatusCode::BAD_REQUEST, Json(InteractionResponse::Empty));
    }
    let payload = payload.unwrap();
    if let Some(t) = payload.get("type") {
        let r = if t == 1 {
            (
                StatusCode::OK,
                Json(InteractionResponse::Ping(PingResponse { response_type: 1 })),
            )
        } else {
            (StatusCode::BAD_REQUEST, Json(InteractionResponse::Empty))
        };
        r
    } else {
        (StatusCode::OK, Json(InteractionResponse::Empty))
    }
}
