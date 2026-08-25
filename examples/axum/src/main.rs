use open_passkey_axum::{
    passkey_router, MemoryChallengeStore, MemoryCredentialStore, PasskeyConfig,
};
use std::sync::Arc;
use tower_http::services::ServeDir;

#[tokio::main]
async fn main() {
    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".into());
    let config = PasskeyConfig {
        rp_id: "localhost".into(),
        rp_display_name: "Open Passkey Axum Example".into(),
        origin: format!("http://localhost:{port}"),
        additional_origins: None,
        challenge_length: 32,
        challenge_timeout_seconds: 300,
        allow_multiple_credentials: false,
    };

    let challenge_store = Arc::new(MemoryChallengeStore::new());
    let credential_store = Arc::new(MemoryCredentialStore::new());

    let passkey = passkey_router(config, challenge_store, credential_store);

    let app = axum::Router::new()
        .nest("/passkey", passkey)
        .fallback_service(ServeDir::new("static"));

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .unwrap();
    println!("Axum example running on http://localhost:{port}");
    axum::serve(listener, app).await.unwrap();
}
