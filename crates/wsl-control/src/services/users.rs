use crate::error::AppResult;
use crate::state::AppState;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use wsl_types::{CreateUserRequest, UpdateUserRequest, User};

pub struct UserService {
    state: AppState,
}

impl UserService {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    pub async fn list(&self) -> AppResult<Vec<User>> {
        let rows: Vec<(Uuid, String, Option<String>, Option<String>, bool, DateTime<Utc>, DateTime<Utc>)> =
            sqlx::query_as(
                "SELECT id, email, display_name, external_id, active, created_at, updated_at FROM users ORDER BY email",
            )
            .fetch_all(&self.state.db)
            .await?;
        Ok(rows
            .into_iter()
            .map(
                |(id, email, display_name, external_id, active, created_at, updated_at)| User {
                    id,
                    email,
                    display_name,
                    external_id,
                    active,
                    created_at,
                    updated_at,
                },
            )
            .collect())
    }

    pub async fn get(&self, id: Uuid) -> AppResult<Option<User>> {
        let row: Option<(Uuid, String, Option<String>, Option<String>, bool, DateTime<Utc>, DateTime<Utc>)> =
            sqlx::query_as(
                "SELECT id, email, display_name, external_id, active, created_at, updated_at FROM users WHERE id = $1",
            )
            .bind(id)
            .fetch_optional(&self.state.db)
            .await?;
        Ok(row.map(
            |(id, email, display_name, external_id, active, created_at, updated_at)| User {
                id,
                email,
                display_name,
                external_id,
                active,
                created_at,
                updated_at,
            },
        ))
    }

    pub async fn create(&self, req: CreateUserRequest) -> AppResult<User> {
        let row: (
            Uuid,
            String,
            Option<String>,
            Option<String>,
            bool,
            DateTime<Utc>,
            DateTime<Utc>,
        ) = sqlx::query_as(
            r#"
                INSERT INTO users (email, display_name, external_id, active)
                VALUES ($1, $2, $3, $4)
                RETURNING id, email, display_name, external_id, active, created_at, updated_at
                "#,
        )
        .bind(&req.email)
        .bind(&req.display_name)
        .bind(&req.external_id)
        .bind(req.active)
        .fetch_one(&self.state.db)
        .await?;
        Ok(User {
            id: row.0,
            email: row.1,
            display_name: row.2,
            external_id: row.3,
            active: row.4,
            created_at: row.5,
            updated_at: row.6,
        })
    }

    pub async fn update(&self, id: Uuid, req: UpdateUserRequest) -> AppResult<Option<User>> {
        let row: Option<(
            Uuid,
            String,
            Option<String>,
            Option<String>,
            bool,
            DateTime<Utc>,
            DateTime<Utc>,
        )> = sqlx::query_as(
            r#"
                UPDATE users SET
                  display_name = COALESCE($2, display_name),
                  active = COALESCE($3, active),
                  updated_at = NOW()
                WHERE id = $1
                RETURNING id, email, display_name, external_id, active, created_at, updated_at
                "#,
        )
        .bind(id)
        .bind(&req.display_name)
        .bind(req.active)
        .fetch_optional(&self.state.db)
        .await?;

        if req.active == Some(false) {
            crate::services::sessions::SessionService::new(self.state.clone())
                .revoke_user_sessions(id)
                .await?;
        }

        Ok(row.map(
            |(id, email, display_name, external_id, active, created_at, updated_at)| User {
                id,
                email,
                display_name,
                external_id,
                active,
                created_at,
                updated_at,
            },
        ))
    }

    pub async fn delete(&self, id: Uuid) -> AppResult<bool> {
        crate::services::sessions::SessionService::new(self.state.clone())
            .revoke_user_sessions(id)
            .await?;
        let r = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(id)
            .execute(&self.state.db)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    #[allow(dead_code)]
    pub async fn find_by_email(&self, email: &str) -> AppResult<Option<User>> {
        let row: Option<(Uuid, String, Option<String>, Option<String>, bool, DateTime<Utc>, DateTime<Utc>)> =
            sqlx::query_as(
                "SELECT id, email, display_name, external_id, active, created_at, updated_at FROM users WHERE email = $1",
            )
            .bind(email)
            .fetch_optional(&self.state.db)
            .await?;
        Ok(row.map(
            |(id, email, display_name, external_id, active, created_at, updated_at)| User {
                id,
                email,
                display_name,
                external_id,
                active,
                created_at,
                updated_at,
            },
        ))
    }
}
