use crate::error::{AppError, AppResult};
use crate::services::audit::AuditService;
use crate::services::groups::GroupService;
use crate::services::ipam::IpamService;
use crate::services::networks::NetworkService;
use crate::state::{hash_token, AppState};
use chrono::{DateTime, Duration, Utc};
use ipnetwork::IpNetwork;
use std::net::IpAddr;
use uuid::Uuid;
use wsl_policy::{evaluate, AccessPolicyDocument, EvaluationInput};
use wsl_types::{
    ClientWireGuardConfig, CreateSessionRequest, CreateSessionResponse, PolicyDecision, Session,
    SessionIdentity, SessionStatus,
};

pub struct SessionService {
    state: AppState,
}

impl SessionService {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    pub async fn list(&self) -> AppResult<Vec<Session>> {
        let rows = self.fetch_sessions(None).await?;
        Ok(rows)
    }

    pub async fn create(
        &self,
        user_id: Uuid,
        user_email: &str,
        req: CreateSessionRequest,
    ) -> AppResult<CreateSessionResponse> {
        // Validate device ownership
        let device: Option<(Uuid, String, bool)> = sqlx::query_as(
            "SELECT id, wireguard_public_key, revoked FROM devices WHERE id = $1 AND user_id = $2",
        )
        .bind(req.device_id)
        .bind(user_id)
        .fetch_optional(&self.state.db)
        .await?;
        let Some((_, wg_pub, revoked)) = device else {
            return Err(AppError::NotFound);
        };
        if revoked {
            return Err(AppError::Forbidden);
        }

        let network = NetworkService::new(self.state.clone())
            .get(req.network_id)
            .await?
            .ok_or(AppError::NotFound)?;

        let gateway: Option<(Uuid, String, String, i64)> = sqlx::query_as(
            r#"
            SELECT id, public_key, endpoint, config_version
            FROM gateways
            WHERE network_id = $1
            ORDER BY last_heartbeat_at DESC NULLS LAST
            LIMIT 1
            "#,
        )
        .bind(req.network_id)
        .fetch_optional(&self.state.db)
        .await?;
        let Some((gateway_id, gw_pub, gw_endpoint, _cfg_ver)) = gateway else {
            return Err(AppError::bad_request("no gateway registered for network"));
        };

        let groups = GroupService::new(self.state.clone())
            .user_group_names(user_id)
            .await?;
        let policies = load_active_policies(&self.state).await?;
        let decision = evaluate(
            &policies,
            &EvaluationInput {
                user_email,
                groups: &groups,
                resource: &network.name,
                posture: &req.posture,
                device_managed: true,
            },
        );

        let mut decision = decision;
        if let Some(name) = decision.policy_name.clone() {
            if let Some((pid, ver, commit)) = policy_meta(&self.state, &name).await? {
                decision.policy_id = Some(pid);
                decision.policy_version = Some(ver);
                decision.git_commit = commit;
            }
        }

        metrics::counter!("wsl_policy_decisions").increment(1);
        if !decision.allow {
            metrics::counter!("wsl_policy_denials").increment(1);
            AuditService::new(self.state.clone())
                .record(
                    "session.create",
                    Some("deny"),
                    Some(user_id),
                    Some(req.device_id),
                    Some(&network.name),
                    decision.policy_id,
                    decision.policy_version,
                    decision.git_commit.as_deref(),
                    serde_json::json!({ "reason": decision.reason }),
                )
                .await?;
            return Err(AppError::Forbidden);
        }

        let duration_secs = decision.session_duration_secs.unwrap_or(8 * 3600);
        let expires_at = Utc::now() + Duration::seconds(duration_secs);
        let session_id = Uuid::new_v4();

        // Insert session with placeholder IP then allocate
        sqlx::query(
            r#"
            INSERT INTO sessions
              (id, user_id, device_id, gateway_id, network_id, policy_id, policy_version,
               assigned_ip, status, expires_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,'0.0.0.0'::inet,'active',$8)
            "#,
        )
        .bind(session_id)
        .bind(user_id)
        .bind(req.device_id)
        .bind(gateway_id)
        .bind(req.network_id)
        .bind(decision.policy_id)
        .bind(decision.policy_version)
        .bind(expires_at)
        .execute(&self.state.db)
        .await?;

        let assigned = IpamService::new(self.state.clone())
            .allocate(req.network_id, session_id)
            .await?;
        let assigned_ip: ipnetwork::IpNetwork = assigned
            .parse()
            .map_err(|e: ipnetwork::IpNetworkError| AppError::bad_request(e.to_string()))?;
        sqlx::query("UPDATE sessions SET assigned_ip = $2 WHERE id = $1")
            .bind(session_id)
            .bind(assigned_ip)
            .execute(&self.state.db)
            .await?;

        let routes = NetworkService::new(self.state.clone())
            .routes_for(req.network_id)
            .await?;
        let allowed: Vec<ipnetwork::IpNetwork> =
            routes.iter().filter_map(|r| r.parse().ok()).collect();
        let allowed_for_peer = if allowed.is_empty() {
            vec![assigned_ip]
        } else {
            // Peer AllowedIPs on gateway side is the client /32
            vec![assigned_ip]
        };

        sqlx::query(
            r#"
            INSERT INTO wireguard_peers
              (session_id, gateway_id, device_id, public_key, allowed_ips, expires_at)
            VALUES ($1,$2,$3,$4,$5,$6)
            "#,
        )
        .bind(session_id)
        .bind(gateway_id)
        .bind(req.device_id)
        .bind(&wg_pub)
        .bind(&allowed_for_peer)
        .bind(expires_at)
        .execute(&self.state.db)
        .await?;

        // Bump gateway config version
        sqlx::query(
            "UPDATE gateways SET config_version = config_version + 1, updated_at = NOW() WHERE id = $1",
        )
        .bind(gateway_id)
        .execute(&self.state.db)
        .await?;

        AuditService::new(self.state.clone())
            .record(
                "session.create",
                Some("allow"),
                Some(user_id),
                Some(req.device_id),
                Some(&network.name),
                decision.policy_id,
                decision.policy_version,
                decision.git_commit.as_deref(),
                serde_json::json!({ "session_id": session_id, "assigned_ip": assigned }),
            )
            .await?;

        metrics::counter!("wsl_active_sessions").increment(1);

        let client_allowed = if routes.is_empty() {
            vec![network.cidr.clone()]
        } else {
            routes
        };

        let session = Session {
            id: session_id,
            user_id,
            device_id: req.device_id,
            gateway_id,
            network_id: req.network_id,
            policy_id: decision.policy_id,
            policy_version: decision.policy_version,
            assigned_ip: assigned.clone(),
            status: SessionStatus::Active,
            created_at: Utc::now(),
            expires_at,
        };

        Ok(CreateSessionResponse {
            session,
            decision,
            wireguard: ClientWireGuardConfig {
                interface_address: assigned,
                dns: network.dns_servers,
                peer_public_key: gw_pub,
                peer_endpoint: gw_endpoint,
                allowed_ips: client_allowed,
                persistent_keepalive: 25,
            },
        })
    }

    /// Resolve an overlay address to the identity behind it.
    ///
    /// Used by edge proxies to enforce per-user access on VPN-only endpoints.
    /// Only active, unexpired sessions resolve: a revoked or expired session is
    /// indistinguishable from an unknown address, so the caller denies either
    /// way without needing to interpret status itself.
    ///
    /// The address is matched exactly against the allocation, so one client
    /// cannot borrow another's identity by claiming a neighbouring address.
    pub async fn identity_by_ip(&self, ip: IpAddr) -> AppResult<Option<SessionIdentity>> {
        let host = IpNetwork::new(ip, if ip.is_ipv4() { 32 } else { 128 })
            .map_err(|e| AppError::bad_request(e.to_string()))?;

        let row: Option<(Uuid, Uuid, String, Uuid, IpNetwork, DateTime<Utc>)> = sqlx::query_as(
            r#"
            SELECT s.id, s.user_id, u.email, s.device_id, s.assigned_ip, s.expires_at
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.assigned_ip = $1
              AND s.status = 'active'
              AND s.expires_at > NOW()
              AND u.active = TRUE
            ORDER BY s.created_at DESC
            LIMIT 1
            "#,
        )
        .bind(host)
        .fetch_optional(&self.state.db)
        .await?;

        let Some((session_id, user_id, email, device_id, assigned_ip, expires_at)) = row else {
            return Ok(None);
        };

        let groups = GroupService::new(self.state.clone())
            .user_group_names(user_id)
            .await?;

        Ok(Some(SessionIdentity {
            session_id,
            user_id,
            email,
            device_id,
            groups,
            assigned_ip: assigned_ip.to_string(),
            expires_at,
        }))
    }

    pub async fn revoke(&self, session_id: Uuid) -> AppResult<bool> {
        let r = sqlx::query(
            "UPDATE sessions SET status = 'revoked' WHERE id = $1 AND status = 'active'",
        )
        .bind(session_id)
        .execute(&self.state.db)
        .await?;
        if r.rows_affected() == 0 {
            return Ok(false);
        }
        sqlx::query("DELETE FROM wireguard_peers WHERE session_id = $1")
            .bind(session_id)
            .execute(&self.state.db)
            .await?;
        IpamService::new(self.state.clone())
            .release_session(session_id)
            .await?;
        // bump all related gateways
        sqlx::query(
            r#"
            UPDATE gateways SET config_version = config_version + 1, updated_at = NOW()
            WHERE id IN (SELECT gateway_id FROM sessions WHERE id = $1)
            "#,
        )
        .bind(session_id)
        .execute(&self.state.db)
        .await?;
        Ok(true)
    }

    pub async fn revoke_user_sessions(&self, user_id: Uuid) -> AppResult<()> {
        let ids: Vec<(Uuid,)> =
            sqlx::query_as("SELECT id FROM sessions WHERE user_id = $1 AND status = 'active'")
                .bind(user_id)
                .fetch_all(&self.state.db)
                .await?;
        for (id,) in ids {
            self.revoke(id).await?;
        }
        Ok(())
    }

    pub async fn revoke_device_sessions(&self, device_id: Uuid) -> AppResult<()> {
        let ids: Vec<(Uuid,)> =
            sqlx::query_as("SELECT id FROM sessions WHERE device_id = $1 AND status = 'active'")
                .bind(device_id)
                .fetch_all(&self.state.db)
                .await?;
        for (id,) in ids {
            self.revoke(id).await?;
        }
        Ok(())
    }

    async fn fetch_sessions(&self, user_id: Option<Uuid>) -> AppResult<Vec<Session>> {
        let rows: Vec<(
            Uuid,
            Uuid,
            Uuid,
            Uuid,
            Uuid,
            Option<Uuid>,
            Option<i64>,
            ipnetwork::IpNetwork,
            String,
            DateTime<Utc>,
            DateTime<Utc>,
        )> = if let Some(uid) = user_id {
            sqlx::query_as(
                r#"
                SELECT id, user_id, device_id, gateway_id, network_id, policy_id, policy_version,
                       assigned_ip, status, created_at, expires_at
                FROM sessions WHERE user_id = $1 ORDER BY created_at DESC
                "#,
            )
            .bind(uid)
            .fetch_all(&self.state.db)
            .await?
        } else {
            sqlx::query_as(
                r#"
                SELECT id, user_id, device_id, gateway_id, network_id, policy_id, policy_version,
                       assigned_ip, status, created_at, expires_at
                FROM sessions ORDER BY created_at DESC LIMIT 200
                "#,
            )
            .fetch_all(&self.state.db)
            .await?
        };

        Ok(rows
            .into_iter()
            .map(|r| Session {
                id: r.0,
                user_id: r.1,
                device_id: r.2,
                gateway_id: r.3,
                network_id: r.4,
                policy_id: r.5,
                policy_version: r.6,
                assigned_ip: r.7.to_string(),
                status: match r.8.as_str() {
                    "expired" => SessionStatus::Expired,
                    "revoked" => SessionStatus::Revoked,
                    _ => SessionStatus::Active,
                },
                created_at: r.9,
                expires_at: r.10,
            })
            .collect())
    }
}

async fn load_active_policies(state: &AppState) -> AppResult<Vec<AccessPolicyDocument>> {
    let rows: Vec<(serde_json::Value,)> = sqlx::query_as(
        r#"
        SELECT pv.document
        FROM policies p
        JOIN policy_versions pv ON pv.policy_id = p.id AND pv.version = p.current_version
        "#,
    )
    .fetch_all(&state.db)
    .await?;
    let mut out = Vec::new();
    for (doc,) in rows {
        let yaml = serde_yaml::to_string(&doc).map_err(|e| AppError::Internal(e.into()))?;
        // document stored as JSON mirroring YAML structure
        let parsed: AccessPolicyDocument =
            serde_json::from_value(doc).map_err(|e| AppError::Internal(e.into()))?;
        let _ = yaml;
        out.push(parsed);
    }
    Ok(out)
}

async fn policy_meta(
    state: &AppState,
    name: &str,
) -> AppResult<Option<(Uuid, i64, Option<String>)>> {
    let row: Option<(Uuid, i64, Option<String>)> =
        sqlx::query_as("SELECT id, current_version, git_commit FROM policies WHERE name = $1")
            .bind(name)
            .fetch_optional(&state.db)
            .await?;
    Ok(row)
}

#[allow(dead_code)]
pub fn _hash_unused(s: &str) -> String {
    hash_token(s)
}

#[allow(dead_code)]
pub type _Decision = PolicyDecision;
