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

Verify a guest_report.bin file:

```rust
use sev_snp_utils::{AttestationReport, Policy};

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