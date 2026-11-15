//! The instance header and the host validation it needs.

/// Header naming the instance the token belongs to.
pub const INSTANCE_HEADER: &str = "x-instance-host";

pub(super) use crate::host::is_plausible_host;
