use wsl_types::{PostureResult, PostureSignal};

pub fn collect() -> Vec<PostureSignal> {
    vec![
        PostureSignal {
            name: "os_version".into(),
            result: PostureResult::Pass,
            detail: Some(format!(
                "{}-{}",
                std::env::consts::OS,
                std::env::consts::ARCH
            )),
        },
        PostureSignal {
            name: "agent_version".into(),
            result: PostureResult::Pass,
            detail: Some(env!("CARGO_PKG_VERSION").into()),
        },
        PostureSignal {
            name: "disk_encryption".into(),
            result: PostureResult::Unknown,
            detail: None,
        },
        PostureSignal {
            name: "device_management".into(),
            result: PostureResult::Unsupported,
            detail: None,
        },
    ]
}
