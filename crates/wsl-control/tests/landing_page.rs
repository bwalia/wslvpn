mod common;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use http_body_util::BodyExt;
use sqlx::PgPool;
use tower::ServiceExt;

/// A person who opens the control plane's address in a browser gets a page
/// saying what it is and whether it is up, not a 404.
#[sqlx::test(migrations = "../../migrations")]
async fn the_root_explains_the_service_and_reports_it_up(pool: PgPool) {
    let app = common::app(pool).await;
    let res = app
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let headers = res.headers().clone();
    assert!(headers[header::CONTENT_TYPE]
        .to_str()
        .unwrap()
        .starts_with("text/html"));
    let csp = headers[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
    assert!(
        csp.contains("default-src 'none'"),
        "no scripts or remote loads: {csp}"
    );

    let body = res.into_body().collect().await.unwrap().to_bytes();
    let page = String::from_utf8(body.to_vec()).unwrap();
    assert!(
        page.contains("Operational"),
        "a live database should read as up"
    );
    assert!(
        page.contains("http://localhost:8080 login"),
        "CLI instructions name this server"
    );
    assert!(!page.contains("{{"), "unfilled placeholder");
}
