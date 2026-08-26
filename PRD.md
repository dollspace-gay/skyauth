# 📄 Product Requirements Document (PRD)

# `atproto-oauth-rs`
### Pure Safe Rust AT Protocol OAuth 2.1, DPoP (RFC 9449), & PAR (RFC 9126) Client Library

---

## 1. Executive Summary & Problem Statement

### 1.1 Context
The **AT Protocol (ATProto)** — the decentralized networking foundation behind Bluesky — mandates modern OAuth 2.1 authentication for third-party clients, custom feed generators, labeling services, AppViews, and autonomous bots. Unlike legacy social protocols that rely on static API keys or user passwords, ATProto requires:
1. **RFC 9449 DPoP (Demonstrating Proof-of-Possession)**: Cryptographically binding access and refresh tokens to client-held asymmetric keys (ECDSA P-256) to eliminate token-theft and replay attacks.
2. **RFC 9126 PAR (Pushed Authorization Requests)**: Direct back-channel pushing of authorization parameters to the user's Personal Data Server (PDS) / Authorization Server with signed DPoP headers.
3. **RFC 7636 PKCE (Proof Key for Code Exchange)**: S256 verifier/challenge generation to eliminate authorization code interception.
4. **Decentralized Identity Discovery**: Resolving handles (`alice.bsky.social`), `did:plc`, and `did:web` identifiers to their authoritative PDS and OAuth authorization server endpoints via RFC 9728 and RFC 8414.

### 1.2 The Ecosystem Problem
Currently, virtually all production-grade ATProto OAuth tooling is maintained in TypeScript (`@atproto/oauth-client-node`, `@atproto/oauth-client-browser`). The Rust ecosystem for ATProto (such as `atrium`) focuses primarily on XRPC Lexicon schema compilation and legacy App Password authentication. 

Rust developers building high-performance ATProto services (feed generators, firehose indexers, labeling engines, CLI tools, and web dashboards) lack a standalone, modular, and memory-safe OAuth 2.1 client library that handles the intricate DPoP, PAR, and decentralized identity discovery flows out of the box.

### 1.3 The Solution
`atproto-oauth-rs` is a high-performance, `#![forbid(unsafe_code)]` pure Rust library that provides a comprehensive, turn-key implementation of AT Protocol OAuth 2.1 with full DPoP and PAR support.

---

## 2. Core Vision & Design Principles

1. **Uncompromising Safety (`#![forbid(unsafe_code)]`)**:
   - Zero unsafe blocks in the entire crate root and modules.
   - Built on proven, formally verified, pure-Rust cryptographic primitives (`p256`, `sha2`, `hmac`).
2. **Zero-Panic & Strongly Typed Errors**:
   - Deny `.unwrap()`, `.expect()`, `panic!`, `todo!`, and `unimplemented!` in production paths.
   - All fallible operations return strongly typed `Result<T, AtprotoOAuthError>`.
3. **Spec-Compliant & Turnkey**:
   - Complete implementation of ATProto OAuth specifications, RFC 9449, RFC 9126, RFC 7636, RFC 8414, and RFC 9728.
   - Automatic `DPoP-Nonce` replay-retry negotiation (RFC 9449 § 4.3).
4. **Framework & Runtime Agnostic**:
   - Compatible with `tokio`, `axum`, `actix-web`, `tower`, and lightweight CLI tools.
   - Pluggable storage traits for session states (in-memory sharded, Redis, SQL, file-backed).
5. **High Concurrency & Low Latency**:
   - Sharded lock-free state stores with single-use atomic consumption for replay defense.
   - Sub-millisecond cryptographic proof generation and token verification.

---

## 3. Scope & Feature Requirements

### 3.1 Feature Matrix

| Module / Component | Spec Standard | Description |
| :--- | :--- | :--- |
| **DPoP Engine** | RFC 9449 | Ephemeral ECDSA P-256 key generation, RFC 7517 JWK formatting, signed `dpop+jwt` proof creation (`htm`, `htu`, `jti`, `iat`, `nonce`, `ath`), and automatic server nonce retry. |
| **PKCE Engine** | RFC 7636 | High-entropy 32-byte verifier generation, SHA-256 S256 challenge computation, and constant-time verification. |
| **Identity & Discovery** | RFC 8414 / RFC 9728 | Handle resolution (`com.atproto.identity.resolveHandle`), PLC directory lookups (`plc.directory`), `did:web` `.well-known/did.json`, OAuth protected resource discovery, and authorization server metadata discovery. |
| **Pushed Authorization (PAR)** | RFC 9126 | Direct HTTP POST authorization initiation to PDS with DPoP proof headers and `request_uri` extraction. |
| **Authorization Flow** | RFC 6749 / RFC 7591 | Client metadata document formatting (`/oauth/client-metadata.json`), login URL generation, and callback validation. |
| **Token Exchange & Refresh** | ATProto OAuth | Exchanging authorization codes for access/refresh tokens with DPoP proof, session renewal, and DID extraction. |
| **Session Management** | RFC 2104 / JWT | Pure safe Rust HMAC-SHA256 session token generation, constant-time verification (`constant_time_eq`), and expiration enforcement. |
| **State Storage** | Sharded Concurrency | 64-shard partitioned, TTL-bounded, atomic single-use state store for CSRF and replay defense. |
| **SSRF & Egress Protection** | Security Standard | Strict private IP filtering (RFC 1918, loopback, link-local, cloud metadata `169.254.169.254`) and no-redirect HTTP client enforcement. |

---

## 4. Architectural Blueprint & API Design

### 4.1 Crate Architecture

```
atproto-oauth/
├── src/
│   ├── lib.rs              # Crate root with #![forbid(unsafe_code)] and strict lints
│   ├── client.rs           # High-level AtprotoOAuthClient interface
│   ├── dpop.rs             # DPoPKey, JWK serialization, & RFC 9449 proof generator
│   ├── pkce.rs             # PKCE code_verifier and S256 challenge helpers
│   ├── resolver.rs         # DID, PDS, & RFC 8414/9728 metadata resolver
│   ├── store.rs            # Sharded in-memory and pluggable OAuthStateStore traits
│   ├── session.rs          # HMAC-SHA256 session signing & validation
│   ├── security.rs         # SSRF validation, restricted IP filtering, constant_time_eq
│   ├── types.rs            # Strongly-typed request, response, and metadata models
│   └── error.rs            # Strongly-typed AtprotoOAuthError enum
├── tests/
│   ├── dpop_rfc9449_vectors.rs
│   ├── pkce_rfc7636_vectors.rs
│   ├── discovery_tests.rs
│   ├── token_exchange_tests.rs
│   ├── kani_harnesses.rs       # Formal mathematical proofs via cargo-kani
│   └── adversarial_hardening_tests.rs
├── Cargo.toml
├── LICENSE-MIT
├── LICENSE-APACHE
└── README.md
```

### 4.2 Core API Signatures (Mockup)

```rust
use atproto_oauth::{AtprotoOAuthClient, OAuthClientMetadata, OAuthStateStore};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Configure client metadata
    let metadata = OAuthClientMetadata::builder()
        .client_id("https://feed.example.com/oauth/client-metadata.json")
        .client_name("My Feed Generator")
        .redirect_uri("https://feed.example.com/oauth/callback")
        .build()?;

    // 2. Initialize OAuth client with thread-safe state store
    let client = AtprotoOAuthClient::new(metadata);

    // 3. Initiate login flow (resolves handle, generates PKCE, creates DPoP proof, calls PAR)
    let login_session = client.create_authorization_url("alice.bsky.social").await?;
    println!("Redirect user to: {}", login_session.authorization_url);

    // ... user completes consent on Bluesky and redirects to callback URI ...

    // 4. Exchange authorization code with PDS using DPoP proof
    let auth_result = client
        .exchange_code(&login_session.state, "auth_code_from_callback")
        .await?;

    println!("Authenticated DID: {}", auth_result.did);
    println!("DPoP-Bound Access Token: {}", auth_result.access_token);
    Ok(())
}
```

---

## 5. Security, Threat Model & Formal Proofs

1. **Token Theft & Replay (RFC 9449)**:
   - Tokens issued by the PDS are cryptographically bound to the client's ephemeral ECDSA key. Even if an access token is intercepted in transit, it cannot be used without generating a corresponding DPoP proof signed by the private key.
2. **Authorization Code Interception (RFC 7636)**:
   - S256 PKCE challenges ensure that only the entity possessing the original code verifier can complete the code exchange.
3. **State Poisoning & CSRF**:
   - OAuth state tokens are generated with 256 bits of cryptographic entropy, stored in a 64-shard partitioned memory store, and consumed atomically via `take` (single-use).
4. **Server-Side Request Forgery (SSRF)**:
   - All outbound network calls to PDS or authorization servers strictly pass through `validate_outbound_url` and `is_restricted_ip`, preventing loopback (`127.0.0.1`), private RFC 1918 egress, and cloud metadata (`169.254.169.254`) exfiltration.
5. **Timing Side-Channels**:
   - Signature checks and token verifications utilize constant-time slice comparison (`constant_time_eq`).

### 5.1 Kani Formal Verification Proof Invariants (`tests/kani_harnesses.rs`)
We leverage [Amazon's Kani Rust Model Checker](https://model-checking.github.io/kani/) to mathematically prove functional invariants at compile time:
- **Proof 1: Single-Use State Consumption Guarantee**: Prove that for all symbolic keys $K$, after calling `take(K)`, any subsequent `take(K)` or `get(K)` strictly returns `None`.
- **Proof 2: PKCE S256 Mathematical Correctness**: Prove that `verify_pkce(verifier, challenge)` returns `true` if and only if `challenge == base64url(sha256(verifier))` with zero false-positive verifications across arbitrary symbolic strings.
- **Proof 3: Timestamp Arithmetic Overflow Freedom**: Prove that monotonic time calculations (`created_at + ttl`) cannot overflow or wrap on 32-bit/64-bit architectures.
- **Proof 4: JWK Coordinate Encoding Integrity**: Prove that elliptic curve point extraction and base64url coordinate serialization never produce truncated or out-of-bounds byte sequences.

---

## 6. Implementation Milestones

- [ ] **Milestone 1: Cryptographic & Token Primitives**
  - Extract `DPoPKey`, `PKCE`, `HMAC-SHA256`, and constant-time comparison into isolated modules.
  - Implement full RFC test vectors for RFC 7636 and RFC 9449.
- [ ] **Milestone 2: Identity & Metadata Resolver**
  - Implement handle resolution, `did:plc`, `did:web`, RFC 9728 protected resource discovery, and RFC 8414 metadata discovery.
  - Implement SSRF and restricted IP egress filters.
- [ ] **Milestone 3: PAR & Token Exchange Pipeline**
  - Implement Pushed Authorization Requests (`/oauth/par`) with DPoP headers.
  - Implement `/oauth/token` exchange with automatic `DPoP-Nonce` replay-retry loop.
- [ ] **Milestone 4: Storage & Web Framework Integrations**
  - Implement 64-shard `OAuthStateStore` with TTL pruning.
  - Provide Axum, Actix, and Tower middleware/handlers examples.
- [ ] **Milestone 5: Kani Formal Verification Suite**
  - Implement `tests/kani_harnesses.rs` verifying single-use state consumption, PKCE challenge mapping, and arithmetic safety.
  - Integrate `cargo kani` into continuous integration verification pipeline.
- [ ] **Milestone 6: Documentation, Benchmarks & Crates.io Publication**
  - 100% rustdoc documentation coverage.
  - Latency benchmarks asserting $< 1.0\text{ms}$ proof generation.
  - Publish `v0.1.0` to crates.io and GitHub.

---

## 7. Success Metrics & Performance SLAs

- **Safety & Verification**: 100% `#![forbid(unsafe_code)]`, zero production panics, and 100% passing Kani model checking proofs (`cargo kani`).
- **Latency**:
  - DPoP proof generation: $< 250\,\mu\text{s}$ (p99).
  - PKCE S256 computation: $< 50\,\mu\text{s}$ (p99).
  - Memory footprint: $< 5\,\text{MB}$ under 50,000 active concurrent OAuth sessions.
- **Test Coverage**: $> 90\%$ code coverage across unit, integration, and fuzz test suites.
