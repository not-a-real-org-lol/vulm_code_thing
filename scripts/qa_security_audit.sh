#!/usr/bin/env bash

set -euo pipefail

REPORT_DIR="${REPORT_DIR:-./qa_audit_artifacts}"
mkdir -p "${REPORT_DIR}"

echo "=========================================================="
echo "          QA COMPREHENSIVE SECURITY AUDIT SUITE           "
echo "=========================================================="
echo "Artifacts directory: ${REPORT_DIR}"
echo ""

echo "[1/6] Running Unit and Security Test Suite..."
python3 -m unittest discover tests -v
echo "==> Tests passed successfully."
echo ""

echo "[2/6] Running Trivy Configuration & Misconfiguration Audit..."
if command -v trivy &>/dev/null; then
    trivy config Dockerfile \
        --format table \
        --output "${REPORT_DIR}/trivy_config_report.txt" || true
    cat "${REPORT_DIR}/trivy_config_report.txt"
else
    echo "WARNING: trivy not found in PATH."
fi
echo ""

echo "[3/6] Running Trivy Filesystem Audit (Vulnerabilities, Secrets, Misconfigs)..."
if command -v trivy &>/dev/null; then
    trivy fs . \
        --scanners vuln,secret,misconfig \
        --format table \
        --output "${REPORT_DIR}/trivy_fs_report.txt" || true
    cat "${REPORT_DIR}/trivy_fs_report.txt"
fi
echo ""

echo "[4/6] Generating CycloneDX SBOM via Syft..."
SBOM_FILE="${REPORT_DIR}/sbom.cdx.json"
if command -v syft &>/dev/null; then
    syft dir:. -o cyclonedx-json="${SBOM_FILE}"
    echo "==> Generated SBOM at ${SBOM_FILE}"
else
    echo "WARNING: syft not found in PATH."
fi
echo ""

echo "[5/6] Cross-Scanning SBOM with Grype and Trivy..."
if [[ -f "${SBOM_FILE}" ]]; then
    if command -v grype &>/dev/null; then
        echo "--- Grype Scan on SBOM ---"
        grype "sbom:${SBOM_FILE}" \
            -o table \
            > "${REPORT_DIR}/grype_sbom_report.txt" || true
        cat "${REPORT_DIR}/grype_sbom_report.txt"
    fi

    if command -v trivy &>/dev/null; then
        echo "--- Trivy Scan on SBOM ---"
        trivy sbom "${SBOM_FILE}" \
            --format table \
            --output "${REPORT_DIR}/trivy_sbom_report.txt" || true
        cat "${REPORT_DIR}/trivy_sbom_report.txt"
    fi
fi
echo ""

echo "[6/6] Cosign Signature Verification Guidance..."
cat << 'EOF'
To verify the published GHCR container image and attested CycloneDX SBOM:

1. Verify Container Image Signature (Keyless via Sigstore OIDC):
   cosign verify \
     --certificate-identity-regexp ".*github.com/not-a-real-org-lol/vulm_code_thing.*" \
     --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
     <IMAGE_DIGEST>

2. Verify Attested CycloneDX SBOM:
   cosign verify-attestation --type cyclonedx \
     --certificate-identity-regexp ".*github.com/not-a-real-org-lol/vulm_code_thing.*" \
     --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
     <IMAGE_DIGEST>
EOF

echo ""
echo "=========================================================="
echo "          QA SECURITY AUDIT COMPLETED SUCCESSFULLY        "
echo "=========================================================="
