//! Mock PLC Directory (`plc.directory`) server harness for DID resolution.
//!
//! Simulates `https://plc.directory/{did}` DID Document lookups with configurable
//! service endpoints, handle bidirectional verification records, and fault injection.

use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Mock PLC Directory server wrapper.
pub struct MockPlcDirectory {
    /// Underlying wiremock server.
    pub server: MockServer,
}

impl MockPlcDirectory {
    /// Starts a fresh mock PLC directory server on a random local port.
    pub async fn start() -> Self {
        let server = MockServer::start().await;
        Self { server }
    }

    /// Returns the base URL of the mock PLC directory server.
    #[must_use]
    pub fn uri(&self) -> String {
        self.server.uri()
    }

    /// Mounts a valid DID document response for the specified DID.
    pub async fn mount_did_document(&self, did: &str, handle: &str, pds_endpoint: &str) {
        let doc = json!({
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1"
            ],
            "id": did,
            "alsoKnownAs": [
                format!("at://{handle}")
            ],
            "service": [
                {
                    "id": "#atproto_pds",
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": pds_endpoint
                }
            ]
        });

        Mock::given(method("GET"))
            .and(path(format!("/{did}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_json(doc),
            )
            .mount(&self.server)
            .await;
    }

    /// Mounts a DID document where `alsoKnownAs` points to a DIFFERENT handle (bidirectional mismatch).
    pub async fn mount_mismatched_handle_document(
        &self,
        did: &str,
        wrong_handle: &str,
        pds_endpoint: &str,
    ) {
        let doc = json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did,
            "alsoKnownAs": [
                format!("at://{wrong_handle}")
            ],
            "service": [
                {
                    "id": "#atproto_pds",
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": pds_endpoint
                }
            ]
        });

        Mock::given(method("GET"))
            .and(path(format!("/{did}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_json(doc),
            )
            .mount(&self.server)
            .await;
    }

    /// Mounts a DID document missing the `#atproto_pds` service entry.
    pub async fn mount_missing_service_document(&self, did: &str, handle: &str) {
        let doc = json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did,
            "alsoKnownAs": [
                format!("at://{handle}")
            ],
            "service": []
        });

        Mock::given(method("GET"))
            .and(path(format!("/{did}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_json(doc),
            )
            .mount(&self.server)
            .await;
    }

    /// Mounts a DID document pointing to an SSRF target URL (e.g. `http://127.0.0.1` or `http://169.254.169.254`).
    pub async fn mount_ssrf_service_document(&self, did: &str, handle: &str, ssrf_endpoint: &str) {
        self.mount_did_document(did, handle, ssrf_endpoint).await;
    }

    /// Mounts a 404 Not Found response for a DID.
    pub async fn mount_did_not_found(&self, did: &str) {
        Mock::given(method("GET"))
            .and(path(format!("/{did}")))
            .respond_with(
                ResponseTemplate::new(404)
                    .insert_header("content-type", "application/json")
                    .set_body_json(json!({
                        "error": "NotFound",
                        "message": "DID document not found in PLC directory"
                    })),
            )
            .mount(&self.server)
            .await;
    }

    /// Mounts a malformed JSON response for a DID.
    pub async fn mount_malformed_json(&self, did: &str) {
        Mock::given(method("GET"))
            .and(path(format!("/{did}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_raw(b"{ invalid json document", "application/json"),
            )
            .mount(&self.server)
            .await;
    }

    /// Mounts a 500 Internal Server Error response for a DID.
    pub async fn mount_server_error(&self, did: &str) {
        Mock::given(method("GET"))
            .and(path(format!("/{did}")))
            .respond_with(
                ResponseTemplate::new(500)
                    .insert_header("content-type", "text/plain")
                    .set_body_string("Internal server error in directory"),
            )
            .mount(&self.server)
            .await;
    }
}
