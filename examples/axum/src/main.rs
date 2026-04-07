use open_passkey_axum::{passkey_router, MemoryChallengeStore, MemoryCredentialStore, PasskeyConfig};
use std::sync::Arc;
use tower_http::services::ServeDir;

#[tokio::main]
async fn main() {
    let config = PasskeyConfig {
        rp_id: "localhost".into(),
        rp_display_name: "Open Passkey Axum Example".into(),
        origin: "http://localhost:3000".into(),
        challenge_length: 32,
        challenge_timeout_seconds: 300,
        session: None,
    };

    let challenge_store = Arc::new(MemoryChallengeStore::new());
    let credential_store = Arc::new(MemoryCredentialStore::new());

    let passkey = passkey_router(config, challenge_store, credential_store);

    let app = axum::Router::new()
        .nest("/passkey", passkey)
        .fallback_service(ServeDir::new("static"));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Axum example running on http://localhost:3000");
    axum::serve(listener, app).await.unwrap();
}
