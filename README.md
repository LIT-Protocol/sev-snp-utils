# sev-snp-utils

AMD SEV-SNP rust utils and primitives.

## Testing

Instead of `cargo test`, run:

```shell
make test
```

## Environment

| Variable                   | Default            | Description                                   |
|----------------------------|--------------------|-----------------------------------------------|
| SEV_SNP_CACHE_PATH         | /var/cache/sev-snp | Path to store downloaded certs.               |
| SEV_SNP_CACHE_ENTRIES_VCEK | 100                | Max cache entries for VCEK certs (in-memory). |

## Attestation

### Report

#### Parsing

Parse a guest_report.bin file:

```rust
use sev_snp_utils::AttestationReport;

fn main() {
    let report = AttestationReport::from_file("./guest_report.bin")
        .expect("failed to parse guest report");
    
    println!("hash: {}", report.sha384_hex());
    println!("version: {:?}", report.version);
    println!("guest_svn: {:?}", report.guest_svn);
    println!("policy: {:?}", report.policy);
    println!("platform_version: {:?}", report.platform_version.raw_decimal());
    println!("measurement: {}", report.measurement_hex());
    println!("report data: {}", report.report_data_hex());
    println!("id key digest: {}", report.id_key_digest_hex());
    println!("author key digest: {}", report.author_key_digest_hex());
    println!("chip id: {}", report.chip_id_hex());
    println!("signature:");
    println!("  r: {}", report.signature.r_hex());
    println!("  s: {}", report.signature.s_hex());
}
```

#### Verification

The verification process:

- Download the ARK, ASK and VCEK DER files from AMD and store them on disk (with in-memory cache as well).
- Downloads are attempted multiple times (10 times with a 4sec sleep) as the ARK end-point is rate limited.
- Verify that the ARK is self-signed, the ASK (AMD SEV intermediate cert) is signed by the ARK and that the VCEK (the CPU cert) is signed by the ASK.
- Take a SHA384 hash of the first part of the report bin (before the signature).
- Verifies the hash against the signature on the file against the cert chain.
- Optionally validate some other things as per the Policy you provide.

Verify a guest_report.bin file:

```rust
use sev_snp_utils::{AttestationReport, Verification, Policy};

async fn verify_guest() {
    let report = AttestationReport::from_file("./guest_report.bin")
        .expect("failed to parse guest report");

    let res = report.verify(Some(Policy::permissive())).await
        .expect("failed to call verify");
    
    if !res {
        panic!("verification failed");
    }
}
```

You may also use `Policy::strict()` or make your own policy:

```rust
let policy = Policy::new(
  true, // require_no_debug
  true, // require_no_ma
  true, // require_no_smt
  true, // require_id_key
  true  // require_author_key
);
```

#### Certs

You may also obtain the certificates to work with them directly:

```rust
use sev_snp_utils::{
    AttestationReport, KdsCertificates, CertFormat,
    get_kds_ark_ask_certs_bytes, get_kds_ark_ask_certs,
    get_kds_ark_ask_certs_and_validate, validate_ark_ask_vcek_certs,
    PRODUCT_NAME_MILAN
};

async fn get_certs() {
    let report = AttestationReport::from_file("./guest_report.bin")
        .expect("failed to parse guest report");

    // VCEK
    
    // Raw bytes as PEM or DER (cached only on disk)
    let pem_bytes = report.get_kds_vcek_cert_bytes(CertFormat::PEM).await
        .expect("failed to get VCEK PEM");

    let der_bytes = report.get_kds_vcek_cert_bytes(CertFormat::DER).await
        .expect("failed to get VCEK DER");

    // X509 (cached in-memory, prefer this method)
    let cert = report.get_kds_vcek_cert().await
        .expect("failed to get VCEK cert");
    
    // ARK & ASK

    // Raw bytes as PEM or DER (cached only on disk)
    let (ark_pem, ask_pem) = get_kds_ark_ask_certs_bytes(PRODUCT_NAME_MILAN, CertFormat::PEM).await
        .expect("failed to get ARK/ASK PEMs");

    // X509 (cached in-memory, prefer this method)
    let (ark_cert, ask_cert) = get_kds_ark_ask_certs(PRODUCT_NAME_MILAN).await
        .expect("failed to get ARK/ASK certs");

    // X509 validated (cached in-memory, prefer this method)
    let (ark_cert, ask_cert) = get_kds_ark_ask_certs_and_validate(PRODUCT_NAME_MILAN).await
        .expect("failed to get ARK/ASK certs");
    
    // Validate
    validate_ark_ask_vcek_certs(&ark_cert, &ask_cert, Some(&cert))
        .expect("failed to validate certs");
}
```