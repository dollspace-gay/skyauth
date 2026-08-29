//! Tower middleware layer and service for DPoP-bound OAuth request authentication.
//!
//! Provides:
//! - [`OAuthAuthLayer`]: Tower [`tower_layer::Layer`] applying DPoP authentication to any compatible service.
//! - [`OAuthAuthService`]: Tower [`tower_service::Service`] extracting, validating, and injecting authenticated sessions.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use http::{header, HeaderValue, Request, Response, StatusCode};
use tower_layer::Layer;
use tower_service::Service;

use super::{AuthenticatedUser, OAuthSessionExtension};
use crate::dpop::{compute_access_token_hash, DPoPVerifier};

/// Tower layer that enforces AT Protocol DPoP OAuth authentication on inbound HTTP requests.
///
/// Inspects the `Authorization: DPoP <access_token>` and `DPoP: <proof_jwt>` headers,
/// verifies the cryptographic proof against the HTTP method and URI, and attaches
/// [`OAuthSessionExtension`] to request extensions before forwarding to the inner service.
#[derive(Debug, Clone)]
pub struct OAuthAuthLayer {
    verifier: Arc<DPoPVerifier>,
    require_ath: bool,
}

impl OAuthAuthLayer {
    /// Creates a new `OAuthAuthLayer` with the provided [`DPoPVerifier`].
    #[must_use]
    pub fn new(verifier: Arc<DPoPVerifier>) -> Self {
        Self {
            verifier,
            require_ath: true,
        }
    }

    /// Configures whether the access token hash (`ath`) claim is strictly required in DPoP proofs.
    #[must_use]
    pub fn with_require_ath(mut self, require_ath: bool) -> Self {
        self.require_ath = require_ath;
        self
    }
}

impl<S> Layer<S> for OAuthAuthLayer {
    type Service = OAuthAuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        OAuthAuthService {
            inner,
            verifier: Arc::clone(&self.verifier),
            require_ath: self.require_ath,
        }
    }
}

/// Tower service that validates DPoP authentication headers on inbound requests.
#[derive(Debug, Clone)]
pub struct OAuthAuthService<S> {
    inner: S,
    verifier: Arc<DPoPVerifier>,
    require_ath: bool,
}

impl<S> OAuthAuthService<S> {
    /// Creates a new `OAuthAuthService` wrapping an inner service.
    pub fn new(inner: S, verifier: Arc<DPoPVerifier>) -> Self {
        Self {
            inner,
            verifier,
            require_ath: true,
        }
    }

    /// Configures whether the access token hash (`ath`) is strictly required in DPoP proofs.
    #[must_use]
    pub fn with_require_ath(mut self, require_ath: bool) -> Self {
        self.require_ath = require_ath;
        self
    }
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for OAuthAuthService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: Default + Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        // 1. Extract Authorization: DPoP <access_token>
        let auth_header = match req.headers().get(header::AUTHORIZATION) {
            Some(h) => match h.to_str() {
                Ok(s) => s,
                Err(_) => return Box::pin(async { Ok(unauthorized_response("invalid_token")) }),
            },
            None => return Box::pin(async { Ok(unauthorized_response("missing_token")) }),
        };

        let access_token = if let Some(token) = auth_header.strip_prefix("DPoP ") {
            token.trim()
        } else if let Some(token) = auth_header.strip_prefix("dpop ") {
            token.trim()
        } else {
            return Box::pin(async { Ok(unauthorized_response("invalid_scheme")) });
        };

        // 2. Extract DPoP proof header
        let dpop_header = match req
            .headers()
            .get("DPoP")
            .or_else(|| req.headers().get("dpop"))
        {
            Some(h) => match h.to_str() {
                Ok(s) => s,
                Err(_) => {
                    return Box::pin(async { Ok(unauthorized_response("invalid_dpop_proof")) })
                }
            },
            None => return Box::pin(async { Ok(unauthorized_response("missing_dpop_proof")) }),
        };

        // 3. Compute expected values
        let htm = req.method().as_str();
        let htu = req.uri().to_string();
        let ath = if self.require_ath {
            Some(compute_access_token_hash(access_token))
        } else {
            None
        };

        // 4. Verify DPoP proof
        let (_claims, jwk) =
            match self
                .verifier
                .verify_proof(dpop_header, htm, &htu, None, ath.as_deref(), None)
            {
                Ok(res) => res,
                Err(err) => {
                    tracing::debug!("DPoP proof verification failed in Tower middleware: {err}");
                    return Box::pin(async { Ok(unauthorized_response("invalid_dpop_proof")) });
                }
            };

        // 5. Build AuthenticatedUser and inject into extensions
        let thumbprint = jwk.thumbprint();
        let user = AuthenticatedUser {
            did: format!("did:key:{thumbprint}"),
            access_token: access_token.to_string(),
            dpop_thumbprint: thumbprint,
            scope: None,
        };

        let ext = OAuthSessionExtension::new(user.clone());
        req.extensions_mut().insert(ext);
        req.extensions_mut().insert(user);

        // 6. Forward to inner service
        let fut = self.inner.call(req);
        Box::pin(fut)
    }
}

/// Helper generating standard HTTP 401 Unauthorized responses with DPoP WWW-Authenticate header.
fn unauthorized_response<ResBody: Default>(error_code: &str) -> Response<ResBody> {
    let mut resp = Response::new(ResBody::default());
    *resp.status_mut() = StatusCode::UNAUTHORIZED;
    let auth_header_val = format!("DPoP error=\"{error_code}\"");
    if let Ok(val) = HeaderValue::from_str(&auth_header_val) {
        resp.headers_mut().insert(header::WWW_AUTHENTICATE, val);
    }
    resp
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;
    use crate::dpop::DPoPKey;
    use std::convert::Infallible;
    use tower::service_fn;
    use tower_service::Service;

    #[tokio::test]
    async fn test_tower_dpop_auth_success() {
        let key = DPoPKey::generate();
        let expected_thumbprint = key.jwk_thumbprint();
        let access_token = "valid_access_token_123";
        let ath = compute_access_token_hash(access_token);
        let uri = "https://pds.example.com/xrpc/app.bsky.actor.getProfile";

        let proof = key.create_proof("GET", uri, None, Some(&ath)).unwrap();

        let verifier = Arc::new(DPoPVerifier::new());
        let layer = OAuthAuthLayer::new(verifier);

        let target_jkt = expected_thumbprint.clone();
        let inner_service = service_fn(move |req: Request<()>| {
            let expected_jkt = target_jkt.clone();
            async move {
                let user = req.extensions().get::<AuthenticatedUser>().cloned();
                assert!(user.is_some());
                let user = user.unwrap();
                assert_eq!(user.access_token, "valid_access_token_123");
                assert_eq!(user.dpop_thumbprint, expected_jkt);
                Ok::<Response<String>, Infallible>(Response::new("OK".to_string()))
            }
        });

        let mut service = layer.layer(inner_service);

        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::AUTHORIZATION, format!("DPoP {access_token}"))
            .header("DPoP", proof)
            .body(())
            .unwrap();

        let resp = service.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.body(), "OK");
    }

    #[tokio::test]
    async fn test_tower_missing_dpop_proof_returns_401() {
        let verifier = Arc::new(DPoPVerifier::new());
        let layer = OAuthAuthLayer::new(verifier);

        let inner_service = service_fn(|_req: Request<()>| async move {
            Ok::<Response<String>, Infallible>(Response::new("OK".to_string()))
        });

        let mut service = layer.layer(inner_service);

        let req = Request::builder()
            .method("GET")
            .uri("https://pds.example.com/xrpc/app.bsky.feed.getTimeline")
            .header(header::AUTHORIZATION, "DPoP token_without_proof")
            .body(())
            .unwrap();

        let resp = service.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(resp.headers().contains_key(header::WWW_AUTHENTICATE));
    }
}
