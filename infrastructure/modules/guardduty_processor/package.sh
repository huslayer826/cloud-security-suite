#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"
ZIP_PATH="${SCRIPT_DIR}/guardduty_processor_lambda.zip"

rm -rf "${BUILD_DIR}" "${ZIP_PATH}"
mkdir -p "${BUILD_DIR}"

cp -R "${REPO_ROOT}/shared" "${BUILD_DIR}/shared"
mkdir -p "${BUILD_DIR}/tools"
cp "${REPO_ROOT}/tools/__init__.py" "${BUILD_DIR}/tools/__init__.py"
cp -R "${REPO_ROOT}/tools/guardduty_processor" "${BUILD_DIR}/tools/guardduty_processor"
cp "${SCRIPT_DIR}/lambda_handler_wrapper.py" "${BUILD_DIR}/lambda_handler_wrapper.py"

rm -rf "${BUILD_DIR}/shared/tests"
rm -rf "${BUILD_DIR}/tools/guardduty_processor/tests"
find "${BUILD_DIR}" -type d -name "__pycache__" -prune -exec rm -rf {} +
find "${BUILD_DIR}" -type f -name "*.pyc" -delete

(
  cd "${BUILD_DIR}"
  zip -qr "${ZIP_PATH}" .
)

echo "Created ${ZIP_PATH}"
