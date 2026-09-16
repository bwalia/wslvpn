use utoipa::OpenApi;
use wsl_types::*;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "WSL Zero Trust VPN API",
        version = "0.1.0",
        description = "Control plane REST API"
    ),
    paths(),
    components(schemas(
        HealthResponse,
        ErrorBody,
        User,
        UserRole,
        CreateUserRequest,
        UpdateUserRequest,
        Group,
        CreateGroupRequest,
        Device,
        RegisterDeviceRequest,
        RegisterDeviceResponse,
        Network,
        CreateNetworkRequest,
        Policy,
        PolicyVersion,
        PolicyDecision,
        Session,
        SessionIdentity,
        CreateSessionRequest,
        CreateSessionResponse,
        ClientWireGuardConfig,
        Gateway,
        RegisterGatewayRequest,
        RegisterGatewayResponse,
        RotateGatewayTokenResponse,
        GatewayConfig,
        GatewayPeer,
        GatewayHeartbeatRequest,
        AuditEvent,
        ActorType,
        PostureSignal,
        PostureResult,
        SessionStatus,
    )),
    tags(
        (name = "health", description = "Health and metrics"),
        (name = "users", description = "Users"),
        (name = "devices", description = "Devices"),
        (name = "sessions", description = "Sessions"),
        (name = "gateways", description = "Gateways"),
    )
)]
pub struct ApiDoc;
