use crate::error::AppResult;
use crate::state::AppState;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use wsl_types::{CreateGroupRequest, Group};

pub struct GroupService {
    state: AppState,
}

impl GroupService {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    pub async fn list(&self) -> AppResult<Vec<Group>> {
        let rows: Vec<(Uuid, String, Option<String>, DateTime<Utc>, DateTime<Utc>)> =
            sqlx::query_as(
                "SELECT id, name, description, created_at, updated_at FROM groups ORDER BY name",
            )
            .fetch_all(&self.state.db)
            .await?;
        Ok(rows
            .into_iter()
            .map(|(id, name, description, created_at, updated_at)| Group {
                id,
                name,
                description,
                created_at,
                updated_at,
            })
            .collect())
    }

    pub async fn get(&self, id: Uuid) -> AppResult<Option<Group>> {
        let row: Option<(Uuid, String, Option<String>, DateTime<Utc>, DateTime<Utc>)> =
            sqlx::query_as(
                "SELECT id, name, description, created_at, updated_at FROM groups WHERE id = $1",
            )
            .bind(id)
            .fetch_optional(&self.state.db)
            .await?;
        Ok(
            row.map(|(id, name, description, created_at, updated_at)| Group {
                id,
                name,
                description,
                created_at,
                updated_at,
            }),
        )
    }

    pub async fn create(&self, req: CreateGroupRequest) -> AppResult<Group> {
        let row: (Uuid, String, Option<String>, DateTime<Utc>, DateTime<Utc>) = sqlx::query_as(
            r#"
            INSERT INTO groups (name, description)
            VALUES ($1, $2)
            ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, updated_at = NOW()
            RETURNING id, name, description, created_at, updated_at
            "#,
        )
        .bind(&req.name)
        .bind(&req.description)
        .fetch_one(&self.state.db)
        .await?;
        Ok(Group {
            id: row.0,
            name: row.1,
            description: row.2,
            created_at: row.3,
            updated_at: row.4,
        })
    }

    pub async fn add_member(&self, group_id: Uuid, user_id: Uuid) -> AppResult<()> {
        sqlx::query(
            "INSERT INTO group_memberships (group_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )
        .bind(group_id)
        .bind(user_id)
        .execute(&self.state.db)
        .await?;
        Ok(())
    }

    pub async fn remove_member(&self, group_id: Uuid, user_id: Uuid) -> AppResult<()> {
        sqlx::query("DELETE FROM group_memberships WHERE group_id = $1 AND user_id = $2")
            .bind(group_id)
            .bind(user_id)
            .execute(&self.state.db)
            .await?;
        Ok(())
    }

    pub async fn user_group_names(&self, user_id: Uuid) -> AppResult<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            r#"
            SELECT g.name FROM groups g
            JOIN group_memberships m ON m.group_id = g.id
            WHERE m.user_id = $1
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.state.db)
        .await?;
        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    pub async fn delete(&self, id: Uuid) -> AppResult<bool> {
        let r = sqlx::query("DELETE FROM groups WHERE id = $1")
            .bind(id)
            .execute(&self.state.db)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    #[allow(dead_code)]
    pub async fn find_by_name(&self, name: &str) -> AppResult<Option<Group>> {
        let row: Option<(Uuid, String, Option<String>, DateTime<Utc>, DateTime<Utc>)> =
            sqlx::query_as(
                "SELECT id, name, description, created_at, updated_at FROM groups WHERE name = $1",
            )
            .bind(name)
            .fetch_optional(&self.state.db)
            .await?;
        Ok(
            row.map(|(id, name, description, created_at, updated_at)| Group {
                id,
                name,
                description,
                created_at,
                updated_at,
            }),
        )
    }
}
