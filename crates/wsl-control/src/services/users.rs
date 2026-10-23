use crate::error::{AppError, AppResult};
use crate::state::AppState;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use wsl_types::{CreateUserRequest, UpdateUserRequest, User, UserRole};

pub struct UserService {
    state: AppState,
}

impl UserService {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    pub async fn list(&self) -> AppResult<Vec<User>> {
        let rows: Vec<(Uuid, String, Option<String>, Option<String>, bool, String, DateTime<Utc>, DateTime<Utc>)> =
            sqlx::query_as(
                "SELECT id, email, display_name, external_id, active, role, created_at, updated_at FROM users ORDER BY email",
            )
            .fetch_all(&self.state.db)
            .await?;
        Ok(rows
            .into_iter()
            .map(
                |(id, email, display_name, external_id, active, role, created_at, updated_at)| {
                    User {
                        id,
                        email,
                        display_name,
                        external_id,
                        active,
                        role: UserRole::from_db(&role),
                        created_at,
                        updated_at,
                    }
                },
            )
            .collect())
    }

    pub async fn get(&self, id: Uuid) -> AppResult<Option<User>> {
        let row: Option<(Uuid, String, Option<String>, Option<String>, bool, String, DateTime<Utc>, DateTime<Utc>)> =
            sqlx::query_as(
                "SELECT id, email, display_name, external_id, active, role, created_at, updated_at FROM users WHERE id = $1",
            )
            .bind(id)
            .fetch_optional(&self.state.db)
            .await?;
        Ok(row.map(
            |(id, email, display_name, external_id, active, role, created_at, updated_at)| User {
                id,
                email,
                display_name,
                external_id,
                active,
                role: UserRole::from_db(&role),
                created_at,
                updated_at,
            },
        ))
    }

    /// Create a user — or, when one with this email exists and has no
    /// `external_id` yet, give it the one supplied.
    ///
    /// The second case is a directory (OpsAPI, SCIM) claiming an account that
    /// predates it, such as a bootstrap administrator. Only the directory's
    /// own credential reaches this, which is what makes it a statement about
    /// who the person is; an email match at sign-in never links (ADR-0004).
    pub async fn create(&self, req: CreateUserRequest) -> AppResult<User> {
        let row: (
            Uuid,
            String,
            Option<String>,
            Option<String>,
            bool,
            String,
            DateTime<Utc>,
            DateTime<Utc>,
        ) = sqlx::query_as(
            r#"
                INSERT INTO users (email, display_name, external_id, active)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (email) DO UPDATE
                  SET external_id = EXCLUDED.external_id, updated_at = NOW()
                  WHERE EXCLUDED.external_id IS NOT NULL
                    AND (users.external_id IS NULL OR users.external_id = EXCLUDED.external_id)
                RETURNING id, email, display_name, external_id, active, role, created_at, updated_at
                "#,
        )
        .bind(&req.email)
        .bind(&req.display_name)
        .bind(&req.external_id)
        .bind(req.active)
        .fetch_optional(&self.state.db)
        .await
        .map_err(|e| match &e {
            // The external id already belongs to someone else.
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                AppError::Conflict("that external_id already belongs to another user".into())
            }
            _ => AppError::from(e),
        })?
        // The email exists and either no external id was given, or it already
        // carries a different one. Re-pointing an account at another directory
        // identity is never done silently.
        .ok_or_else(|| AppError::Conflict("a user with that email already exists".into()))?;
        Ok(User {
            id: row.0,
            email: row.1,
            display_name: row.2,
            external_id: row.3,
            active: row.4,
            role: UserRole::from_db(&row.5),
            created_at: row.6,
            updated_at: row.7,
        })
    }

    pub async fn update(&self, id: Uuid, req: UpdateUserRequest) -> AppResult<Option<User>> {
        let row: Option<(
            Uuid,
            String,
            Option<String>,
            Option<String>,
            bool,
            String,
            DateTime<Utc>,
            DateTime<Utc>,
        )> = sqlx::query_as(
            r#"
                UPDATE users SET
                  display_name = COALESCE($2, display_name),
                  active = COALESCE($3, active),
                  role = COALESCE($4, role),
                  updated_at = NOW()
                WHERE id = $1
                RETURNING id, email, display_name, external_id, active, role, created_at, updated_at
                "#,
        )
        .bind(id)
        .bind(&req.display_name)
        .bind(req.active)
        .bind(req.role.map(|r| r.as_str()))
        .fetch_optional(&self.state.db)
        .await?;

        // Disabling an account has to reach the data plane, not just the
        // directory: an active session keeps working until its peer is removed
        // from the gateway.
        if req.active == Some(false) {
            crate::services::sessions::SessionService::new(self.state.clone())
                .revoke_user_sessions(id)
                .await?;
        }

        Ok(row.map(
            |(id, email, display_name, external_id, active, role, created_at, updated_at)| User {
                id,
                email,
                display_name,
                external_id,
                active,
                role: UserRole::from_db(&role),
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
        let row: Option<(Uuid, String, Option<String>, Option<String>, bool, String, DateTime<Utc>, DateTime<Utc>)> =
            sqlx::query_as(
                "SELECT id, email, display_name, external_id, active, role, created_at, updated_at FROM users WHERE email = $1",
            )
            .bind(email)
            .fetch_optional(&self.state.db)
            .await?;
        Ok(row.map(
            |(id, email, display_name, external_id, active, role, created_at, updated_at)| User {
                id,
                email,
                display_name,
                external_id,
                active,
                role: UserRole::from_db(&role),
                created_at,
                updated_at,
            },
        ))
    }
}
