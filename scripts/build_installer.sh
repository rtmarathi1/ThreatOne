#!/usr/bin/env bash
# ThreatOne Enterprise - Installer Build Script
# Builds the application and packages it using Qt Installer Framework

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "${SCRIPT_DIR}")"
BUILD_DIR="${PROJECT_ROOT}/build"
INSTALLER_DIR="${PROJECT_ROOT}/installer"
OUTPUT_DIR="${PROJECT_ROOT}/dist"

# Build configuration
BUILD_TYPE="${BUILD_TYPE:-Release}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"

echo "================================================"
echo "  ThreatOne Enterprise - Installer Builder"
echo "================================================"
echo ""

# Step 1: Build the application
echo "[1/4] Building ThreatOne Enterprise (${BUILD_TYPE})..."
cmake -B "${BUILD_DIR}" \
    -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
    -DCMAKE_INSTALL_PREFIX="${INSTALLER_DIR}/packages/com.threatone.core/data" \
    "${PROJECT_ROOT}"

cmake --build "${BUILD_DIR}" -j"${JOBS}"

# Step 2: Install to package data directory
echo "[2/4] Installing to package data directory..."
cmake --install "${BUILD_DIR}"

# Step 3: Check for binarycreator
echo "[3/4] Checking for Qt Installer Framework tools..."

BINARYCREATOR=""
if command -v binarycreator &>/dev/null; then
    BINARYCREATOR="binarycreator"
elif [ -n "${QT_IFW_DIR:-}" ] && [ -x "${QT_IFW_DIR}/bin/binarycreator" ]; then
    BINARYCREATOR="${QT_IFW_DIR}/bin/binarycreator"
elif [ -d "/opt/Qt/Tools/QtInstallerFramework" ]; then
    # Find the latest version
    QT_IFW_LATEST=$(find /opt/Qt/Tools/QtInstallerFramework -maxdepth 1 -type d | sort -V | tail -1)
    if [ -x "${QT_IFW_LATEST}/bin/binarycreator" ]; then
        BINARYCREATOR="${QT_IFW_LATEST}/bin/binarycreator"
    fi
fi

if [ -z "${BINARYCREATOR}" ]; then
    echo "ERROR: binarycreator not found."
    echo ""
    echo "Please install Qt Installer Framework and either:"
    echo "  - Add it to your PATH"
    echo "  - Set QT_IFW_DIR environment variable to the IFW installation directory"
    echo "  - Install it to /opt/Qt/Tools/QtInstallerFramework/"
    echo ""
    echo "Download from: https://download.qt.io/official_releases/qt-installer-framework/"
    exit 1
fi

echo "  Found: ${BINARYCREATOR}"

# Step 4: Build installer
echo "[4/4] Building installer package..."
mkdir -p "${OUTPUT_DIR}"

PLATFORM="$(uname -s)"
case "${PLATFORM}" in
    Linux*)
        INSTALLER_NAME="ThreatOneEnterprise-1.0.0-linux-installer"
        ;;
    Darwin*)
        INSTALLER_NAME="ThreatOneEnterprise-1.0.0-macos-installer"
        ;;
    MINGW*|MSYS*|CYGWIN*)
        INSTALLER_NAME="ThreatOneEnterprise-1.0.0-windows-installer"
        ;;
    *)
        INSTALLER_NAME="ThreatOneEnterprise-1.0.0-installer"
        ;;
esac

"${BINARYCREATOR}" \
    --offline-only \
    -c "${INSTALLER_DIR}/config/config.xml" \
    -p "${INSTALLER_DIR}/packages" \
    "${OUTPUT_DIR}/${INSTALLER_NAME}"

echo ""
echo "================================================"
echo "  Installer built successfully!"
echo "  Output: ${OUTPUT_DIR}/${INSTALLER_NAME}"
echo "================================================"
