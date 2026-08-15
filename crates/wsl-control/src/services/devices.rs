use crate::error::{AppError, AppResult};
use crate::state::AppState;
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;
use wsl_types::{Device, RegisterDeviceRequest, RegisterDeviceResponse};

pub struct DeviceService {
    state: AppState,
}

impl DeviceService {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    pub async fn list(&self) -> AppResult<Vec<Device>> {
        let rows = sqlx::query_as::<
            _,
            (
                Uuid,
                Uuid,
                String,
                String,
                Option<String>,
                Option<String>,
                String,
                bool,
                DateTime<Utc>,
                DateTime<Utc>,
            ),
        >(
            r#"
            SELECT id, user_id, name, platform, os_version, agent_version,
                   wireguard_public_key, revoked, created_at, updated_at
            FROM devices ORDER BY created_at DESC
            "#,
        )
        .fetch_all(&self.state.db)
        .await?;
        Ok(rows.into_iter().map(map_device).collect())
    }

    pub async fn get(&self, id: Uuid) -> AppResult<Option<Device>> {
        let row = sqlx::query_as::<
            _,
            (
                Uuid,
                Uuid,
                String,
                String,
                Option<String>,
                Option<String>,
                String,
                bool,
                DateTime<Utc>,
                DateTime<Utc>,
            ),
        >(
            r#"
            SELECT id, user_id, name, platform, os_version, agent_version,
                   wireguard_public_key, revoked, created_at, updated_at
            FROM devices WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.state.db)
        .await?;
        Ok(row.map(map_device))
    }

    pub async fn register(
        &self,
        user_id: Uuid,
        req: RegisterDeviceRequest,
    ) -> AppResult<RegisterDeviceResponse> {
        if req.wireguard_public_key.len() < 40 {
            return Err(AppError::bad_request("invalid wireguard public key"));
        }
        let row = sqlx::query_as::<
            _,
            (
                Uuid,
                Uuid,
                String,
                String,
                Option<String>,
                Option<String>,
                String,
                bool,
                DateTime<Utc>,
                DateTime<Utc>,
            ),
        >(
            r#"
            INSERT INTO devices (user_id, name, platform, os_version, agent_version, wireguard_public_key)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (wireguard_public_key) DO UPDATE SET
              name = EXCLUDED.name,
              platform = EXCLUDED.platform,
              os_version = EXCLUDED.os_version,
              agent_version = EXCLUDED.agent_version,
              revoked = FALSE,
              updated_at = NOW()
            RETURNING id, user_id, name, platform, os_version, agent_version,
                      wireguard_public_key, revoked, created_at, updated_at
            "#,
        )
        .bind(user_id)
        .bind(&req.name)
        .bind(&req.platform)
        .bind(&req.os_version)
        .bind(&req.agent_version)
        .bind(&req.wireguard_public_key)
        .fetch_one(&self.state.db)
        .await?;

        let device = map_device(row);
        let expires_at = Utc::now() + Duration::days(30);
        // Lightweight device certificate placeholder (PEM-ish marker); production should use real CA.
        let certificate_pem = format!(
            "-----BEGIN WSL DEVICE CERT-----\nDevice-Id: {}\nUser-Id: {}\nExpires: {}\n-----END WSL DEVICE CERT-----\n",
            device.id, user_id, expires_at.to_rfc3339()
        );
        let fingerprint = crate::state::hash_token(&certificate_pem);
        sqlx::query(
            r#"
            INSERT INTO device_certificates (device_id, certificate_pem, fingerprint, expires_at)
            VALUES ($1, $2, $3, $4)
            "#,
        )
        .bind(device.id)
        .bind(&certificate_pem)
        .bind(&fingerprint)
        .bind(expires_at)
        .execute(&self.state.db)
        .await?;

        crate::services::audit::AuditService::new(self.state.clone())
            .record(
                "device.register",
                Some("allow"),
                Some(user_id),
                Some(device.id),
                None,
                None,
                None,
                None,
                serde_json::json!({ "platform": device.platform }),
            )
            .await?;

        metrics::counter!("wsl_device_registrations").increment(1);

        Ok(RegisterDeviceResponse {
            device,
            certificate_pem,
            expires_at,
        })
    }

    pub async fn revoke(&self, id: Uuid) -> AppResult<bool> {
        let r = sqlx::query("UPDATE devices SET revoked = TRUE, updated_at = NOW() WHERE id = $1")
            .bind(id)
            .execute(&self.state.db)
            .await?;
        if r.rows_affected() == 0 {
            return Ok(false);
        }
        crate::services::sessions::SessionService::new(self.state.clone())
            .revoke_device_sessions(id)
            .await?;
        Ok(true)
    }
}

fn map_device(
    row: (
        Uuid,
        Uuid,
        String,
        String,
        Option<String>,
        Option<String>,
        String,
        bool,
        DateTime<Utc>,
        DateTime<Utc>,
    ),
) -> Device {
    Device {
        id: row.0,
        user_id: row.1,
        name: row.2,
        platform: row.3,
        os_version: row.4,
        agent_version: row.5,
        wireguard_public_key: row.6,
        revoked: row.7,
        created_at: row.8,
        updated_at: row.9,
    }
}
