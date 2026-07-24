use crate::{routes, state::AppState};
use axum::{
    Router,
    http::{HeaderValue, Method, header},
    routing::get_service,
};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::{
    compression::CompressionLayer,
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

pub async fn create_app(state: AppState) -> Router {
    let cors = {
        let settings = state.settings.read().await;
        if settings.web_cors_origin_list() == vec!["*"] {
            CorsLayer::new().allow_origin(Any)
        } else {
            let origins = settings
                .web_cors_origin_list()
                .into_iter()
                .filter_map(|value| value.parse::<HeaderValue>().ok())
                .collect::<Vec<_>>();
            CorsLayer::new().allow_origin(origins)
        }
    }
    .allow_methods([
        Method::GET,
        Method::POST,
        Method::PUT,
        Method::PATCH,
        Method::DELETE,
    ])
    .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]);
    let static_dir = state.settings.read().await.web_static_dir.clone();
    let mut app = routes::router();
    if !static_dir.trim().is_empty() && std::path::Path::new(&static_dir).is_dir() {
        let index = std::path::Path::new(&static_dir).join("index.html");
        let service = ServeDir::new(&static_dir).fallback(ServeFile::new(index));
        app = app.fallback_service(get_service(service));
    }
    app.with_state(state)
        .layer(CompressionLayer::new())
        .layer(cors)
        .layer(TraceLayer::new_for_http())
}
