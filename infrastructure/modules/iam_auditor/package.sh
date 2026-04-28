#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"
ZIP_PATH="${SCRIPT_DIR}/iam_auditor_lambda.zip"

rm -rf "${BUILD_DIR}" "${ZIP_PATH}"
mkdir -p "${BUILD_DIR}"

python3.11 -m pip install \
  --target "${BUILD_DIR}" \
  --only-binary=:all: \
  jinja2 \
  rich

cp -R "${REPO_ROOT}/shared" "${BUILD_DIR}/shared"
mkdir -p "${BUILD_DIR}/tools"
cp "${REPO_ROOT}/tools/__init__.py" "${BUILD_DIR}/tools/__init__.py"
cp -R "${REPO_ROOT}/tools/iam_auditor" "${BUILD_DIR}/tools/iam_auditor"
cp "${SCRIPT_DIR}/lambda_handler.py" "${BUILD_DIR}/lambda_handler.py"

rm -rf "${BUILD_DIR}/tools/iam_auditor/tests"
rm -rf "${BUILD_DIR}/tools/iam_auditor/sample_output"
find "${BUILD_DIR}" -type d -name "__pycache__" -prune -exec rm -rf {} +
find "${BUILD_DIR}" -type f -name "*.pyc" -delete

(
  cd "${BUILD_DIR}"
  zip -qr "${ZIP_PATH}" .
)

echo "Created ${ZIP_PATH}"
