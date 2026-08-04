#!/usr/bin/env bash
# Real CycloneDX SBOM generation from requirements.txt.
# Usage: ./release/generate_sbom.sh
set -e
cd "$(dirname "$0")/.."
pip install cyclonedx-bom --break-system-packages -q 2>/dev/null || true
cyclonedx-py requirements -i requirements.txt -o release/sbom.cyclonedx.json --output-format json
echo "SBOM written to release/sbom.cyclonedx.json"
