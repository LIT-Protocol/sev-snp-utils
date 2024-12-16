#[cfg(feature = "vmsa-sev")]
pub use crate::guest::measure::vmsa_sev::*;

#[cfg(not(feature = "vmsa-sev"))]
pub use crate::guest::measure::vmsa_builtin::*;
