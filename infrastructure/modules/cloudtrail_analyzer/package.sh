#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"
ZIP_PATH="${SCRIPT_DIR}/cloudtrail_analyzer_lambda.zip"
PYTHON_BIN="${PYTHON_BIN:-$(command -v python3.11 || command -v python3)}"

rm -rf "${BUILD_DIR}" "${ZIP_PATH}"
mkdir -p "${BUILD_DIR}"

"${PYTHON_BIN}" -m pip install \
  --target "${BUILD_DIR}" \
  --only-binary=:all: \
  jinja2 \
  rich

cp -R "${REPO_ROOT}/shared" "${BUILD_DIR}/shared"
mkdir -p "${BUILD_DIR}/tools"
cp "${REPO_ROOT}/tools/__init__.py" "${BUILD_DIR}/tools/__init__.py"
cp -R "${REPO_ROOT}/tools/cloudtrail_analyzer" "${BUILD_DIR}/tools/cloudtrail_analyzer"
cp "${SCRIPT_DIR}/lambda_handler_wrapper.py" "${BUILD_DIR}/lambda_handler_wrapper.py"

rm -rf "${BUILD_DIR}/shared/tests"
rm -rf "${BUILD_DIR}/tools/cloudtrail_analyzer/tests"
rm -rf "${BUILD_DIR}/tools/cloudtrail_analyzer/sample_data"
find "${BUILD_DIR}" -type d -name "__pycache__" -prune -exec rm -rf {} +
find "${BUILD_DIR}" -type f -name "*.pyc" -delete

(
  cd "${BUILD_DIR}"
  zip -qr "${ZIP_PATH}" .
)

echo "Created ${ZIP_PATH}"
