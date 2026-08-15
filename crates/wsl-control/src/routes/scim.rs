use crate::error::{AppError, AppResult};
use crate::services::groups::GroupService;
use crate::services::users::UserService;
use crate::state::AppState;
use axum::{
    extract::{Path, Query, State},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use wsl_types::{CreateGroupRequest, CreateUserRequest, UpdateUserRequest};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/ServiceProviderConfig", get(service_provider_config))
        .route("/ResourceTypes", get(resource_types))
        .route("/Schemas", get(schemas))
        .route("/Users", get(list_users).post(create_user))
        .route(
            "/Users/{id}",
            get(get_user)
                .put(replace_user)
                .patch(patch_user)
                .delete(delete_user),
        )
        .route("/Groups", get(list_groups).post(create_group))
        .route("/Groups/{id}", get(get_group).delete(delete_group))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ListResponse<T> {
    schemas: Vec<&'static str>,
    total_results: usize,
    resources: Vec<T>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ScimUser {
    schemas: Vec<&'static str>,
    id: String,
    user_name: String,
    display_name: Option<String>,
    active: bool,
    emails: Vec<ScimEmail>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ScimEmail {
    value: String,
    #[serde(default = "primary_true")]
    primary: bool,
}

fn primary_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScimUserCreate {
    user_name: String,
    display_name: Option<String>,
    active: Option<bool>,
    emails: Option<Vec<ScimEmail>>,
    external_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PatchOp {
    op: String,
    path: Option<String>,
    value: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct PatchRequest {
    #[serde(rename = "Operations")]
    operations: Vec<PatchOp>,
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    #[allow(dead_code)]
    filter: Option<String>,
}

async fn service_provider_config() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "patch": { "supported": true },
        "bulk": { "supported": false },
        "filter": { "supported": true, "maxResults": 200 },
        "changePassword": { "supported": false },
        "sort": { "supported": false },
        "etag": { "supported": false },
        "authenticationSchemes": [{
            "type": "oauthbearertoken",
            "name": "OAuth Bearer Token",
            "description": "Authentication via OpsAPI/service bearer token"
        }]
    }))
}

async fn resource_types() -> Json<serde_json::Value> {
    Json(serde_json::json!([
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "User",
            "name": "User",
            "endpoint": "/Users",
            "schema": "urn:ietf:params:scim:schemas:core:2.0:User"
        },
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "Group",
            "name": "Group",
            "endpoint": "/Groups",
            "schema": "urn:ietf:params:scim:schemas:core:2.0:Group"
        }
    ]))
}

async fn schemas() -> Json<serde_json::Value> {
    Json(serde_json::json!([]))
}

fn to_scim_user(u: wsl_types::User) -> ScimUser {
    ScimUser {
        schemas: vec!["urn:ietf:params:scim:schemas:core:2.0:User"],
        id: u.id.to_string(),
        user_name: u.email.clone(),
        display_name: u.display_name,
        active: u.active,
        emails: vec![ScimEmail {
            value: u.email,
            primary: true,
        }],
    }
}

async fn list_users(
    State(state): State<AppState>,
    Query(_q): Query<ListQuery>,
) -> AppResult<Json<ListResponse<ScimUser>>> {
    let users = UserService::new(state).list().await?;
    let resources: Vec<_> = users.into_iter().map(to_scim_user).collect();
    Ok(Json(ListResponse {
        schemas: vec!["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        total_results: resources.len(),
        resources,
    }))
}

async fn create_user(
    State(state): State<AppState>,
    Json(body): Json<ScimUserCreate>,
) -> AppResult<Json<ScimUser>> {
    let email = body
        .emails
        .as_ref()
        .and_then(|e| e.first())
        .map(|e| e.value.clone())
        .unwrap_or(body.user_name);
    let user = UserService::new(state)
        .create(CreateUserRequest {
            email,
            display_name: body.display_name,
            external_id: body.external_id,
            active: body.active.unwrap_or(true),
        })
        .await?;
    Ok(Json(to_scim_user(user)))
}

async fn get_user(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> AppResult<Json<ScimUser>> {
    UserService::new(state)
        .get(id)
        .await?
        .map(to_scim_user)
        .map(Json)
        .ok_or(AppError::NotFound)
}

async fn replace_user(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<ScimUserCreate>,
) -> AppResult<Json<ScimUser>> {
    UserService::new(state.clone())
        .update(
            id,
            UpdateUserRequest {
                display_name: body.display_name,
                active: body.active,
            },
        )
        .await?
        .map(to_scim_user)
        .map(Json)
        .ok_or(AppError::NotFound)
}

async fn patch_user(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<PatchRequest>,
) -> AppResult<Json<ScimUser>> {
    let mut active = None;
    let mut display_name = None;
    for op in body.operations {
        let op_name = op.op.to_lowercase();
        if op_name == "replace" {
            if op.path.as_deref() == Some("active") {
                active = op.value.as_ref().and_then(|v| v.as_bool());
            } else if op.path.as_deref() == Some("displayName") {
                display_name = op
                    .value
                    .as_ref()
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
            } else if let Some(obj) = op.value.as_ref().and_then(|v| v.as_object()) {
                if let Some(a) = obj.get("active").and_then(|v| v.as_bool()) {
                    active = Some(a);
                }
            }
        }
    }
    UserService::new(state)
        .update(
            id,
            UpdateUserRequest {
                display_name,
                active,
            },
        )
        .await?
        .map(to_scim_user)
        .map(Json)
        .ok_or(AppError::NotFound)
}

async fn delete_user(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    let ok = UserService::new(state).delete(id).await?;
    if !ok {
        return Err(AppError::NotFound);
    }
    Ok(Json(serde_json::json!({})))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ScimGroup {
    schemas: Vec<&'static str>,
    id: String,
    display_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScimGroupCreate {
    display_name: String,
}

async fn list_groups(State(state): State<AppState>) -> AppResult<Json<ListResponse<ScimGroup>>> {
    let groups = GroupService::new(state).list().await?;
    let resources: Vec<_> = groups
        .into_iter()
        .map(|g| ScimGroup {
            schemas: vec!["urn:ietf:params:scim:schemas:core:2.0:Group"],
            id: g.id.to_string(),
            display_name: g.name,
        })
        .collect();
    Ok(Json(ListResponse {
        schemas: vec!["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        total_results: resources.len(),
        resources,
    }))
}

async fn create_group(
    State(state): State<AppState>,
    Json(body): Json<ScimGroupCreate>,
) -> AppResult<Json<ScimGroup>> {
    let g = GroupService::new(state)
        .create(CreateGroupRequest {
            name: body.display_name.clone(),
            description: None,
        })
        .await?;
    Ok(Json(ScimGroup {
        schemas: vec!["urn:ietf:params:scim:schemas:core:2.0:Group"],
        id: g.id.to_string(),
        display_name: g.name,
    }))
}

async fn get_group(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> AppResult<Json<ScimGroup>> {
    let g = GroupService::new(state)
        .get(id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(ScimGroup {
        schemas: vec!["urn:ietf:params:scim:schemas:core:2.0:Group"],
        id: g.id.to_string(),
        display_name: g.name,
    }))
}

async fn delete_group(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    let ok = GroupService::new(state).delete(id).await?;
    if !ok {
        return Err(AppError::NotFound);
    }
    Ok(Json(serde_json::json!({})))
}
