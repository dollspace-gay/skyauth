#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
MANIFEST_FILE="${ROOT_DIR}/schemas/.checksums.sha256"
PROVENANCE_FILE="${ROOT_DIR}/schemas/provenance.json"

managed_files() {
    jq -r '.artifacts[].local_path' "${PROVENANCE_FILE}"
}

sha256_file() {
    sha256sum "$1" | awk '{print $1}'
}

validate_json() {
    jq empty "$1" >/dev/null
}

normalize_json() {
    jq . "$1"
}

generate_manifest() {
    local temporary
    temporary="$(mktemp "${MANIFEST_FILE}.XXXXXX")"
    while IFS= read -r path; do
        printf '%s  %s\n' "$(sha256_file "${ROOT_DIR}/${path}")" "${path}" >>"${temporary}"
    done < <(managed_files)
    mv "${temporary}" "${MANIFEST_FILE}"
}

verify_local() {
    validate_json "${PROVENANCE_FILE}"
    local failed=0
    while IFS= read -r path; do
        local file="${ROOT_DIR}/${path}"
        if [[ ! -f "${file}" ]] || ! validate_json "${file}"; then
            printf 'invalid or missing managed artifact: %s\n' "${path}" >&2
            failed=1
            continue
        fi
        local expected
        expected="$(jq -r --arg path "${path}" '.artifacts[] | select(.local_path == $path) | .local_sha256' "${PROVENANCE_FILE}")"
        if [[ "$(sha256_file "${file}")" != "${expected}" ]]; then
            printf 'local provenance digest mismatch: %s\n' "${path}" >&2
            failed=1
        fi
    done < <(managed_files)
    if ! (cd "${ROOT_DIR}" && sha256sum --check --strict "${MANIFEST_FILE}"); then
        failed=1
    fi
    if [[ "${failed}" -ne 0 ]]; then
        return 1
    fi
    printf 'local specification integrity verified\n'
}

fetch_upstream() {
    local url="$1"
    local path="$2"
    local destination="$3"
    if [[ -n "${SKYAUTH_UPSTREAM_FIXTURE_DIR:-}" ]]; then
        cp "${SKYAUTH_UPSTREAM_FIXTURE_DIR}/${path}" "${destination}"
    else
        curl -fsSL --connect-timeout 10 --max-time 30 "${url}" -o "${destination}"
    fi
}

check_upstream() {
    verify_local
    local temporary_directory
    temporary_directory="$(mktemp -d)"
    trap 'rm -r -- "${temporary_directory}"' RETURN
    local failed=0
    while IFS=$'\t' read -r path url; do
        local raw="${temporary_directory}/raw.json"
        local normalized="${temporary_directory}/normalized.json"
        if ! fetch_upstream "${url}" "${path}" "${raw}" || ! validate_json "${raw}"; then
            printf 'failed to fetch valid upstream JSON: %s\n' "${path}" >&2
            failed=1
            continue
        fi
        normalize_json "${raw}" >"${normalized}"
        if ! cmp -s "${ROOT_DIR}/${path}" "${normalized}"; then
            printf 'upstream specification drift detected: %s\n' "${path}" >&2
            failed=1
        fi
    done < <(jq -r '.artifacts[] | select(.kind == "upstream") | [.local_path, .source_url] | @tsv' "${PROVENANCE_FILE}")
    rm -r -- "${temporary_directory}"
    trap - RETURN
    if [[ "${failed}" -ne 0 ]]; then
        return 1
    fi
    printf 'upstream specification freshness verified\n'
}

sync_upstream() {
    local temporary_directory
    temporary_directory="$(mktemp -d)"
    trap 'rm -r -- "${temporary_directory}"' RETURN
    local commit
    local upstream_date
    if [[ -n "${SKYAUTH_UPSTREAM_FIXTURE_DIR:-}" ]]; then
        commit="fixture"
        upstream_date="1970-01-01T00:00:00Z"
    else
        commit="$(git ls-remote https://github.com/bluesky-social/atproto.git refs/heads/main | awk '{print $1}')"
        upstream_date="$(curl -fsSL --connect-timeout 10 --max-time 30 "https://api.github.com/repos/bluesky-social/atproto/commits/${commit}" | jq -r '.commit.committer.date')"
    fi
    local retrieved_at
    retrieved_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    local updated="${temporary_directory}/provenance.json"
    cp "${PROVENANCE_FILE}" "${updated}"
    while IFS=$'\t' read -r path url; do
        local raw="${temporary_directory}/raw-$(basename "${path}")"
        local staged="${temporary_directory}/staged/${path}"
        mkdir -p "$(dirname "${staged}")"
        fetch_upstream "${url}" "${path}" "${raw}"
        validate_json "${raw}"
        normalize_json "${raw}" >"${staged}"
        local raw_digest
        raw_digest="$(sha256_file "${raw}")"
        local local_digest
        local_digest="$(sha256_file "${staged}")"
        local next="${temporary_directory}/next.json"
        jq \
            --arg path "${path}" \
            --arg commit "${commit}" \
            --arg upstream_date "${upstream_date}" \
            --arg raw_digest "${raw_digest}" \
            --arg local_digest "${local_digest}" \
            '(.artifacts[] | select(.local_path == $path)) |= (.upstream_commit = $commit | .upstream_date = $upstream_date | .upstream_sha256 = $raw_digest | .local_sha256 = $local_digest)' \
            "${updated}" >"${next}"
        mv "${next}" "${updated}"
    done < <(jq -r '.artifacts[] | select(.kind == "upstream") | [.local_path, .source_url] | @tsv' "${PROVENANCE_FILE}")
    while IFS= read -r path; do
        cp "${temporary_directory}/staged/${path}" "${ROOT_DIR}/${path}"
    done < <(jq -r '.artifacts[] | select(.kind == "upstream") | .local_path' "${PROVENANCE_FILE}")
    jq --arg retrieved_at "${retrieved_at}" '.retrieved_at = $retrieved_at' "${updated}" >"${PROVENANCE_FILE}"
    generate_manifest
    rm -r -- "${temporary_directory}"
    trap - RETURN
    verify_local
}

case "${1:---verify}" in
    --verify|--check)
        verify_local
        ;;
    --check-upstream)
        check_upstream
        ;;
    --sync)
        sync_upstream
        ;;
    --generate-manifest)
        generate_manifest
        ;;
    --help|-h)
        printf '%s\n' 'usage: sync_specs.sh --verify|--check-upstream|--sync|--generate-manifest'
        ;;
    *)
        printf 'unknown command: %s\n' "$1" >&2
        exit 2
        ;;
esac
