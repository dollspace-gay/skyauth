#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used, missing_docs)]
#![cfg(feature = "tower")]

mod support;

use std::convert::Infallible;
use std::sync::Arc;

use http::{header, HeaderValue, Method, Request, Response, StatusCode};
use skyauth::dpop::{compute_access_token_hash, DPoPKey, DPoPVerifier};
use skyauth::integrations::tower::{NoncePolicy, RouteAuthorization, RouteScopePolicy};
use skyauth::integrations::AuthenticatedUser;
use support::TestTokenAuthority;
use tower::service_fn;
use tower_layer::Layer;
use tower_service::Service;

const ORIGIN: &str = "https://pds.example.com";
const PATH: &str = "/xrpc/app.bsky.feed.getTimeline";

fn request(token: &str, proof: &str) -> Request<()> {
    Request::builder()
        .method(Method::GET)
        .uri(PATH)
        .header(header::AUTHORIZATION, format!("DPoP {token}"))
        .header("DPoP", proof)
        .body(())
        .unwrap()
}

fn ok_service(
) -> impl Service<Request<()>, Response = Response<String>, Error = Infallible, Future = impl Send> + Clone
{
    service_fn(|req: Request<()>| async move {
        let subject = req
            .extensions()
            .get::<AuthenticatedUser>()
            .map(|user| user.did().to_string())
            .unwrap_or_default();
        Ok::<_, Infallible>(Response::new(subject))
    })
}

#[tokio::test]
async fn accepts_validated_token_bound_proof_and_uses_token_subject() {
    let key = DPoPKey::generate();
    let authority = TestTokenAuthority::new();
    let token = authority.issue(&key.jwk_thumbprint());
    let proof = key
        .create_proof(
            "GET",
            &format!("{ORIGIN}{PATH}"),
            None,
            Some(&compute_access_token_hash(&token)),
        )
        .unwrap();
    let layer = authority.layer(Arc::new(DPoPVerifier::new()));
    let response = layer
        .layer(ok_service())
        .call(request(&token, &proof))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.body(), "did:plc:abcdefgh");
}

#[tokio::test]
async fn rejects_unverifiable_and_untrusted_signatures() {
    let key = DPoPKey::generate();
    let authority = TestTokenAuthority::new();
    let attacker = TestTokenAuthority::new();
    let attacker_token = attacker.issue(&key.jwk_thumbprint());
    let proof = key
        .create_proof(
            "GET",
            &format!("{ORIGIN}{PATH}"),
            None,
            Some(&compute_access_token_hash(&attacker_token)),
        )
        .unwrap();
    let mut service = authority
        .layer(Arc::new(DPoPVerifier::new()))
        .layer(ok_service());

    let arbitrary = request("not-a-token", "not-a-proof");
    assert_eq!(
        service.call(arbitrary).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        service
            .call(request(&attacker_token, &proof))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn rejects_binding_issuer_audience_and_expiry_mismatches() {
    let key = DPoPKey::generate();
    let other_key = DPoPKey::generate();
    let authority = TestTokenAuthority::new();
    let cases = [
        authority.issue(&other_key.jwk_thumbprint()),
        authority.issue_with_claims(
            &key.jwk_thumbprint(),
            "did:plc:abcdefgh",
            "atproto test.scope",
            "https://other-issuer.example.com",
            ORIGIN,
            300,
        ),
        authority.issue_with_claims(
            &key.jwk_thumbprint(),
            "did:plc:abcdefgh",
            "atproto test.scope",
            "https://issuer.example.com",
            "https://other-resource.example.com",
            300,
        ),
        authority.issue_with_claims(
            &key.jwk_thumbprint(),
            "did:plc:abcdefgh",
            "atproto test.scope",
            "https://issuer.example.com",
            ORIGIN,
            -300,
        ),
    ];
    let mut service = authority
        .layer(Arc::new(DPoPVerifier::new()))
        .layer(ok_service());

    for token in cases {
        let proof = key
            .create_proof(
                "GET",
                &format!("{ORIGIN}{PATH}"),
                None,
                Some(&compute_access_token_hash(&token)),
            )
            .unwrap();
        assert_eq!(
            service
                .call(request(&token, &proof))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
}

#[tokio::test]
async fn rejects_duplicate_headers_and_untrusted_host_reconstruction() {
    let key = DPoPKey::generate();
    let authority = TestTokenAuthority::new();
    let token = authority.issue(&key.jwk_thumbprint());
    let proof = key
        .create_proof(
            "GET",
            &format!("{ORIGIN}{PATH}"),
            None,
            Some(&compute_access_token_hash(&token)),
        )
        .unwrap();
    let mut service = authority
        .layer(Arc::new(DPoPVerifier::new()))
        .layer(ok_service());

    let mut duplicate = request(&token, &proof);
    duplicate
        .headers_mut()
        .append("DPoP", HeaderValue::from_static("second-proof"));
    assert_eq!(
        service.call(duplicate).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );

    let attacker_proof = key
        .create_proof(
            "GET",
            &format!("https://attacker.example.com{PATH}"),
            None,
            Some(&compute_access_token_hash(&token)),
        )
        .unwrap();
    let mut spoofed = request(&token, &attacker_proof);
    spoofed.headers_mut().insert(
        header::HOST,
        HeaderValue::from_static("attacker.example.com"),
    );
    assert_eq!(
        service.call(spoofed).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn rejects_a_second_use_of_an_accepted_proof() {
    let key = DPoPKey::generate();
    let authority = TestTokenAuthority::new();
    let token = authority.issue(&key.jwk_thumbprint());
    let proof = key
        .create_proof(
            "GET",
            &format!("{ORIGIN}{PATH}"),
            None,
            Some(&compute_access_token_hash(&token)),
        )
        .unwrap();
    let mut service = authority
        .layer(Arc::new(DPoPVerifier::new()))
        .layer(ok_service());

    assert_eq!(
        service
            .call(request(&token, &proof))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        service
            .call(request(&token, &proof))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn rotates_required_nonce_and_rejects_previous_nonce() {
    let key = DPoPKey::generate();
    let authority = TestTokenAuthority::new();
    let token = authority.issue(&key.jwk_thumbprint());
    let routes = RouteScopePolicy::new(Vec::<String>::new(), NoncePolicy::Required);
    let mut service = authority
        .layer_with_policy(Arc::new(DPoPVerifier::new()), routes)
        .layer(ok_service());
    let ath = compute_access_token_hash(&token);
    let first_proof = key
        .create_proof("GET", &format!("{ORIGIN}{PATH}"), None, Some(&ath))
        .unwrap();
    let first = service.call(request(&token, &first_proof)).await.unwrap();
    assert_eq!(first.status(), StatusCode::UNAUTHORIZED);
    let nonce = first.headers().get("DPoP-Nonce").unwrap().to_str().unwrap();

    let second_proof = key
        .create_proof("GET", &format!("{ORIGIN}{PATH}"), Some(nonce), Some(&ath))
        .unwrap();
    let second = service.call(request(&token, &second_proof)).await.unwrap();
    assert_eq!(second.status(), StatusCode::OK);
    assert_ne!(second.headers().get("DPoP-Nonce").unwrap(), nonce);

    let replayed_nonce_proof = key
        .create_proof("GET", &format!("{ORIGIN}{PATH}"), Some(nonce), Some(&ath))
        .unwrap();
    assert_eq!(
        service
            .call(request(&token, &replayed_nonce_proof))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn enforces_exact_route_scopes_after_authentication() {
    let key = DPoPKey::generate();
    let authority = TestTokenAuthority::new();
    let token = authority.issue(&key.jwk_thumbprint());
    let routes = RouteScopePolicy::new(Vec::<String>::new(), NoncePolicy::Disabled).with_route(
        RouteAuthorization::new(
            Method::GET,
            PATH,
            ["admin.scope".to_string()],
            NoncePolicy::Disabled,
        ),
    );
    let proof = key
        .create_proof(
            "GET",
            &format!("{ORIGIN}{PATH}"),
            None,
            Some(&compute_access_token_hash(&token)),
        )
        .unwrap();
    let response = authority
        .layer_with_policy(Arc::new(DPoPVerifier::new()), routes)
        .layer(ok_service())
        .call(request(&token, &proof))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
