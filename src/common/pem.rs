// Taken from pkix which is not compatible with OSX M1.

/// Type of the various `PEM_*` constants supplied to `pem_to_der` / `der_to_pem`.
pub struct PemGuard {
    begin: &'static str,
    end: &'static str,
}

macro_rules! pem_guard {
    ($n:expr) => {
        &PemGuard {
            begin: concat!("-----BEGIN ", $n, "-----"),
            end: concat!("-----END ", $n, "-----"),
        }
    }
}

// Ref. RFC7468, although these are not universally respected.
pub const PEM_CERTIFICATE: &'static PemGuard = pem_guard!("CERTIFICATE");
pub const PEM_CERTIFICATE_REQUEST: &'static PemGuard = pem_guard!("CERTIFICATE REQUEST");
pub const PEM_ENCRYPTED_PRIVATE_KEY: &'static PemGuard = pem_guard!("ENCRYPTED PRIVATE KEY");
pub const PEM_PRIVATE_KEY: &'static PemGuard = pem_guard!("PRIVATE KEY");
pub const PEM_PUBLIC_KEY: &'static PemGuard = pem_guard!("PUBLIC KEY");
pub const PEM_CMS: &'static PemGuard = pem_guard!("CMS");

/// Convert PEM to DER. If `guard` is specified (e.g. as PEM_CERTIFICATE), then the guardlines are
/// verified to match the expected string. Otherwise, the guardlines are verified to generally have
/// the correct form.
///
/// On failure (due to guardlines syntax or an illegal PEM character), returns None.
pub fn pem_to_der(pem: &str, guard: Option<&PemGuard>) -> Option<Vec<u8>> {
    let mut lines = pem.lines();

    let begin = match lines.next() {
        Some(l) => l,
        None => return None,
    };
    let end = match lines.last() {
        Some(l) => l,
        None => return None,
    };

    if let Some(g) = guard {
        if begin != g.begin || end != g.end {
            return None;
        }
    } else {
        if !begin.starts_with("-----BEGIN ") || !begin.ends_with("-----") ||
            !end.starts_with("-----END") || !end.ends_with("-----") {
            return None;
        }
    }

    let body_start = pem.char_indices()
        .skip(begin.len())
        .skip_while(|t| t.1.is_whitespace())
        .next().unwrap().0;
    let body_end = pem.rmatch_indices(&end).next().unwrap().0;

    base64::decode(&pem[body_start..body_end]).ok()
}

/// Convert DER to PEM. The guardlines use the identifying string chosen by `guard`
/// (e.g. PEM_CERTIFICATE).
pub fn der_to_pem<T: ?Sized + AsRef<[u8]>>(der: &T, guard: &PemGuard) -> String {
    let mut pem = String::new();
    let b64_string = base64::encode(&der.as_ref());

    pem.push_str(guard.begin);
    pem.push('\n');
    if der.as_ref().len() > 0 {
        pem.push_str(b64_string.as_str());
        pem.push('\n');
    }
    pem.push_str(guard.end);
    pem.push('\n');

    pem
}