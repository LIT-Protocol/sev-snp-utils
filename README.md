# sev-snp-utils

AMD SEV-SNP rust utils and primitives.

## Environment

| Key                        | Default            | Description                         |
|----------------------------|--------------------|-------------------------------------|
| SEV_SNP_CACHE_PATH         | /var/cache/sev-snp | Path to store downloaded certs.     |
| SEV_SNP_CACHE_MEM_VCEK_LEN | 100                | Entries for VCEK cert memory cache. |

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
    println!("measurement: {}", report.measurement_hex());
    println!("id key digest: {}", report.id_key_digest_hex());
    println!("author key digest: {}", report.author_key_digest_hex());
    println!("chip id: {}", report.chip_id_hex());
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