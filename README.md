# 🔐 `atproto-oauth-rs`

> **Pure Safe Rust (`#![forbid(unsafe_code)]`) AT Protocol OAuth 2.1 Client with RFC 9449 DPoP, RFC 9126 PAR, & RFC 7636 PKCE**

---

## 🌟 Highlights

- **100% Pure Safe Rust**: `#![forbid(unsafe_code)]` enforced across the entire codebase with zero `unsafe` blocks.
- **RFC 9449 DPoP**: Ephemeral ECDSA P-256 key generation, RFC 7517 JWK formatting, signed `dpop+jwt` proof tokens, and automatic `DPoP-Nonce` retry negotiation.
- **RFC 9126 PAR**: Pushed Authorization Requests with signed DPoP headers.
- **RFC 7636 PKCE**: S256 verifier/challenge generation and verification.
- **Decentralized Identity Discovery**: Seamless handle resolution (`alice.bsky.social`), `did:plc`, `did:web`, RFC 9728 protected resource discovery, and RFC 8414 OAuth authorization server discovery.
- **Replay & SSRF Defense**: 64-shard partitioned single-use state store and strict private network egress filtering.

---

## 📖 Product Requirements Document (PRD)

For full architectural blueprints, API designs, security specifications, and milestone roadmaps, see [**`PRD.md`**](PRD.md).

---

## 📄 License

Dual-licensed under either:
- **MIT License** ([LICENSE-MIT](LICENSE-MIT))
- **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE))
