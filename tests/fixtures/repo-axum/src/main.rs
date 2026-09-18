fn app() -> Router {
    Router::new()
        .route("/api/admin", get(admin_handler).layer(RequireAuth))
        .route("/api/report", post(report_handler))
}

async fn report_handler(Json(payload): Json<Report>) -> impl IntoResponse {
    sqlx::query(&format!("select * from users where id = {}", payload.id));
    StatusCode::OK
}
