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

#### Request

To request a report from a SEV-SNP capable CPU (the same functionality as `sev-guest-get-report`):

```rust
use sev_snp_utils::{AttestationReport, Requester};

fn main() {
    let report = AttestationReport::request()
        .expect("failed to request guest report");

    println!("version: {:?}", report.version);
    
    // Or raw bytes
    let report_bytes = AttestationReport::request_raw()
        .expect("failed to request guest report");

    println!("bytes len: {:?}", report_bytes.len());
}
```

#### Parsing

Parse a guest_report.bin file from `sev-guest-get-report` (or one saved from `AttestationReport::request_raw()`):

```rust
use sev_snp_utils::AttestationReport;

fn main() {
    let report = AttestationReport::from_file("./guest_report.bin")
        .expect("failed to parse guest report");
    
    println!("version: {:?}", report.version);
    println!("guest_svn: {:?}", report.guest_svn);
    println!("policy: {:?}", report.policy);
    println!("platform_version: {:?}", report.platform_version.raw_decimal());
    println!("measurement: {}", report.measurement_hex());
    println!("report data: {}", report.report_data_hex());
    println!("id key digest: {}", report.id_key_digest_hex());
    println!("author key digest: {}", report.author_key_digest_hex());
    println!("chip id: {}", report.chip_id_hex());
    println!("hash: {}", report.sha384_hex());
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

## Measurement

### Calculating launch digest

```rust
use std::fs;
use std::path::PathBuf;
use sev_snp_utils::{
    calc_launch_digest, SevMode, CpuType
};

fn main() {
    let ovmf_path = PathBuf::from("./OVMF_CODE.fd");
    let kernel_path = PathBuf::from("./vmlinuz");
    let append_path = PathBuf::from("./vmlinuz.cmdline");
    let initrd_path = PathBuf::from("./initrd.img");

    let append = fs::read_to_string(&append_path)
        .expect(format!("failed to read '{:?}'", &append_path).as_str());
    
    let digest = calc_launch_digest(SevMode::SevSnp, 64, ovmf_path.as_path(),
                                    Some(kernel_path.as_path()), Some(initrd_path.as_path()), 
                                    Some(append.as_str()))
        .expect("failed to calculate launch digest");
}
```

## Identity

### Preparation

Before you can generate an `IdBlock` and `IdAuthInfo` you'll first need to create some ECDSA keys (pem files).

```shell
openssl genpkey -algorithm ec -pkeyopt ec_paramgen_curve:"P-384" -out id-key.pem

# Author key is optional.
openssl genpkey -algorithm ec -pkeyopt ec_paramgen_curve:"P-384" -out author-key.pem
```

### Generating

#### Method interface

```rust
use std::path::PathBuf;
use sev_snp_utils::{
    create_identity_block, LaunchDigest, FamilyId, ImageId, ToBase64
};

fn main() {
    let id_key_pem = PathBuf::from("./id-key.pem");
    let author_key_pem = PathBuf::from("./author-key.pem");

    let measurement = LaunchDigest::from_str("ffb0cb7f01a5d5b122430d66f211326ab5cf11a9a5d3189ec53adf9a60730bc63d9856fe9fe602abd662861d0ee36007");
    let family_id = FamilyId::zeroes();
    let image_id = ImageId::from_str("ffb0cb7f01a5d5b122430d66f211326a");
    let guest_svn = 0;
    let policy = 0x30000;
    
    let (id_block, id_auth_info) = create_identity_block(measurement, family_id, image_id,
                                                         guest_svn, policy, id_key_pem.as_path(),
                                                         Some(author_key_pem.as_path()))
        .expect("failed to create identity block");
    
    println!("id_block: {}", id_block.to_base64().unwrap()); // Or call save_base64().
    println!("id_auth_info: {}", id_auth_info.to_base64().unwrap());
}
```

#### Object interface

```rust
use std::path::PathBuf;
use sev_snp_utils::{
    IdBlock, LaunchDigest, FamilyId, ImageId, BlockSigner, ToBase64
};

fn main() {
    let id_key_pem = PathBuf::from("./id-key.pem");
    let author_key_pem = PathBuf::from("./author-key.pem");

    let id_block = IdBlock::default()
        .with_ld(LaunchDigest::from_str("ffb0cb7f01a5d5b122430d66f211326ab5cf11a9a5d3189ec53adf9a60730bc63d9856fe9fe602abd662861d0ee36007"))
        .with_family_id(FamilyId::zeroes())
        .with_image_id(ImageId::from_str("ffb0cb7f01a5d5b122430d66f211326a"))
        .with_guest_svn(0)
        .with_policy(0x30000);

    let id_auth_info = id_block.sign(id_key_pem.as_path(), Some(author_key_pem.as_path()))
        .expect("failed to sign id block");
    
    println!("id_block: {}", id_block.to_base64().unwrap()); // Or call save_base64().
    println!("id_auth_info: {}", id_auth_info.to_base64().unwrap());
}
```

### Fingerprints

```rust
use std::path::PathBuf;
use sev_snp_utils::{
    fingerprint_id_key_as_hex
};

fn main() {
    let id_key_pem = PathBuf::from("./id-key.pem");
    let author_key_pem = PathBuf::from("./author-key.pem");

    let id_fingerprint = fingerprint_id_key_as_hex(id_key_pem.as_path()) // or fingerprint_id_key()
        .expect("failed to fingerprint");
    let author_fingerprint = fingerprint_id_key_as_hex(author_key_pem.as_path())
        .expect("failed to fingerprint");
    
    println!("id_fingerprint: {}", id_fingerprint);
    println!("author_fingerprint: {}", author_fingerprint);
}
```

## Key Derivation

The guest can ask the firmware to provide a key derived from a root key contained within the AMD SEV-SNP PSP. This key may be used by the guest for any purpose it chooses, such as sealing keys (i.e. for disk encryption) or communicating with external entities. Usually the intention will be that this can be used to create a key that's only known to the guest.

### Preparation

Prepare the request using `DerivedKeyRequestedBuilder` like so:

```rust
let options = DerivedKeyRequestBuilder::new()
    .with_tcb_version()
    .with_image_id()
    .build();
```

The example above mixes the TCB version provided by the guest and the image ID provided at launch into the derived key.

Here is the complete list of builder methods you can use to mix different data into the derived key:

- `with_tcb_version`: mixes in the TCB version provided by the guest.
- `with_svn`: mixes in the SVN of the guest.
- `with_launch_measurement`: mixes in the measurement of the guest at launch.
- `with_family_id`: mixes in the family ID at launch.
- `with_image_id`: mixes in the image ID at launch.
- `with_policy`: mixes in the guest policy at launch.

### Request

Pass in the `DerivedKeyRequestOptions` struct to the `DerivedKey::request` method like so:

```rust
let derived_key = DerivedKey::request(options).unwrap();
```

### Examples

Here is a MCVE of how to request a derived key from the firmware:

```rust
use sev_snp_utils::guest::derived_key::get_derived_key::{DerivedKeyRequester, DerivedKeyRequestBuilder};
use sev_snp_utils::guest::derived_key::derived_key::DerivedKey;

fn main() {
    let options = DerivedKeyRequestBuilder::new()
        .with_tcb_version()
        .with_image_id()
        .build();
    println!("Options: {:?}", options);

    let derived_key = DerivedKey::request(options).unwrap();
    println!("Derived Key: {:?}", derived_key);
}
```

## Misc

- AMD SEV-SNP Firmware ABI Specification: https://www.amd.com/system/files/TechDocs/56860.pdf