//! The configuration files this repository ships must load.
//!
//! Every one of them is something a reader will copy: the development example,
//! the production template, the Compose file, and the Helm chart's rendered
//! output. A field renamed in `config.rs` without updating them turns into a
//! startup failure for whoever copies it next, which is exactly the class of
//! drift a test can hold shut.

use std::path::{Path, PathBuf};
use wsl_control::config::Config;

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is crates/wsl-control.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("resolve repository root")
}

/// Set the variables the production template references. Scoped to this
/// process; tests in one binary share an environment, so the values are
/// distinctive enough to be recognised if one leaks into an assertion.
fn set_production_env() {
    for (key, value) in [
        ("WSL_DATABASE_URL", "postgres://user:pw@db.example.com/wsl"),
        ("WSL_OIDC_ISSUER", "https://idp.example.com"),
        ("WSL_OIDC_CLIENT_ID", "wslvpn"),
        ("WSL_OIDC_CLIENT_SECRET", "oidc-client-secret-value"),
        ("WSL_OPS_SERVICE_TOKEN", "ops-token-long-enough-to-pass"),
        (
            "WSL_GATEWAY_REGISTRATION_TOKEN",
            "gateway-token-long-enough",
        ),
        ("WSL_SCIM_SERVICE_TOKEN", "scim-token-long-enough-to-pass"),
    ] {
        std::env::set_var(key, value);
    }
}

#[test]
fn the_development_example_loads() {
    let path = repo_root().join("config/control.example.yaml");
    let cfg = Config::load(&path).expect("config/control.example.yaml should load");
    assert!(
        cfg.is_local(),
        "the development example must address a loopback host; it enables dev login"
    );
}

#[test]
fn the_compose_config_loads() {
    let path = repo_root().join("deploy/compose/control.yaml");
    Config::load(&path).expect("deploy/compose/control.yaml should load");
}

#[test]
fn the_production_template_loads_with_its_environment_set() {
    set_production_env();
    let path = repo_root().join("config/control.production.example.yaml");
    let cfg = Config::load(&path).expect("the production template should load");

    assert!(!cfg.is_local());
    assert!(
        !cfg.identity.dev_login_enabled,
        "the production template must not enable dev login"
    );
    assert!(
        !cfg.server.expose_docs,
        "the production template must not expose the API document"
    );
    assert!(
        !cfg.bootstrap.admin_emails.is_empty(),
        "a production deployment with no administrator cannot be administered"
    );
    assert_eq!(
        cfg.database.url, "postgres://user:pw@db.example.com/wsl",
        "secrets should come from the environment, not the file"
    );
}

#[test]
fn a_missing_secret_stops_startup_and_names_the_variable() {
    // Tests in one binary share an environment and run in parallel, so this
    // references a name nothing ever sets rather than unsetting a shared one.
    set_production_env();
    let template =
        std::fs::read_to_string(repo_root().join("config/control.production.example.yaml"))
            .unwrap();
    let broken = template.replace(
        "${WSL_OPS_SERVICE_TOKEN}",
        "${WSL_DELIBERATELY_UNSET_FOR_THIS_TEST}",
    );
    let path = std::env::temp_dir().join(format!(
        "wsl-missing-secret-{}-{:?}.yaml",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::write(&path, broken).unwrap();

    let err = Config::load(&path).expect_err("a missing secret must not start the process");
    let message = format!("{err:#}");
    assert!(
        message.contains("WSL_DELIBERATELY_UNSET_FOR_THIS_TEST"),
        "the error should name the missing variable: {message}"
    );
    let _ = std::fs::remove_file(&path);
}

/// The chart's ConfigMap is rendered from the same field names the loader
/// expects. Rendering needs Helm, so the check reads the template's literal
/// keys instead — enough to catch a rename, without a toolchain dependency.
#[test]
fn the_helm_configmap_uses_field_names_the_loader_knows() {
    let template =
        std::fs::read_to_string(repo_root().join("deploy/helm/wslvpn/templates/configmap.yaml"))
            .expect("read the chart's configmap template");

    for key in [
        "public_url",
        "expose_docs",
        "max_connections",
        "acquire_timeout_secs",
        "dev_login_enabled",
        "ops_service_token",
        "gateway_registration_token",
        "scim_service_token",
        "admin_emails",
        "rate_limit",
        "window_secs",
    ] {
        assert!(
            template.contains(key),
            "the chart no longer emits `{key}`; the loader still requires it"
        );
    }
}

#[test]
fn the_development_example_would_be_refused_on_a_public_host() {
    // Point the development example at a public URL and it must refuse to
    // start: it carries example secrets and enables dev login. This is the
    // check that stops "it worked locally" from becoming a production deploy.
    let raw = std::fs::read_to_string(repo_root().join("config/control.example.yaml")).unwrap();
    let promoted = raw.replace(
        "public_url: \"http://localhost:8080\"",
        "public_url: \"https://vpn.example.com\"",
    );
    let path = std::env::temp_dir().join(format!(
        "wsl-promoted-{}-{:?}.yaml",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::write(&path, promoted).unwrap();

    let err = Config::load(&path).expect_err("example secrets must not reach a public deployment");
    let message = format!("{err:#}");
    assert!(
        message.contains("example value") || message.contains("dev_login_enabled"),
        "unexpected rejection: {message}"
    );
    let _ = std::fs::remove_file(&path);
}
