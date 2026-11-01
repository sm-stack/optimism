//! The CPU features op-aggregator's build may target. leanVM picks its kernels when it is
//! compiled, not when it runs: a binary built for a CPU with them ends in an illegal instruction on
//! one without, and one built without them proves about six times slower. So op-aggregator's
//! release builds target them, and the binary checks them before it runs leanVM.

/// A CPU feature the build may target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Feature {
    /// Its name, as `target_feature` spells it.
    name: &'static str,
    /// Whether this binary was compiled to use it.
    compiled: bool,
    /// Whether this CPU has it.
    present: bool,
}

/// The [`Feature`]s named, detected with `$detect`.
macro_rules! detect {
    ($detect:ident: $($name:tt),* $(,)?) => {
        [$(Feature { name: $name, compiled: cfg!(target_feature = $name), present: $detect!($name) }),*]
    };
}

/// x86-64-v3, which the release build targets and the compiler may use anywhere, and leanVM's
/// kernels' extensions.
#[cfg(target_arch = "x86_64")]
fn features() -> impl IntoIterator<Item = Feature> {
    detect!(is_x86_feature_detected:
        "sse3", "ssse3", "sse4.1", "sse4.2", "popcnt", "cmpxchg16b", "avx", "avx2", "bmi1", "bmi2",
        "f16c", "fma", "lzcnt", "movbe", "pclmulqdq", "aes", "gfni", "vpclmulqdq", "avx512f",
        "avx512bw", "avx512vbmi")
}

/// leanVM's kernels' extensions.
#[cfg(target_arch = "aarch64")]
fn features() -> impl IntoIterator<Item = Feature> {
    use std::arch::is_aarch64_feature_detected;
    detect!(is_aarch64_feature_detected: "aes", "sha3", "sve2")
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn features() -> impl IntoIterator<Item = Feature> {
    []
}

/// The features this binary was compiled to use that the CPU lacks: it cannot run here.
pub fn missing() -> Vec<&'static str> {
    features().into_iter().filter(|f| f.compiled && !f.present).map(|f| f.name).collect()
}

/// Whether this binary has leanVM's fast kernels: carry-less multiplication over vectors (x86-64
/// with VPCLMULQDQ and AVX2, or ARM with the AES extension's PMULL). Without them proving is about
/// six times slower.
pub const fn fast_kernels() -> bool {
    cfg!(any(
        all(target_arch = "x86_64", target_feature = "vpclmulqdq", target_feature = "avx2"),
        all(target_arch = "aarch64", target_feature = "aes")
    ))
}

#[cfg(test)]
mod tests {
    /// A binary runs on the machine it was built and tested on.
    #[test]
    fn the_build_host_has_what_the_binary_uses() {
        assert_eq!(super::missing(), Vec::<&str>::new());
    }
}
