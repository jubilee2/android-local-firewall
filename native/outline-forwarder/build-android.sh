#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${1:-${SCRIPT_DIR}/../../app/build/generated/jniLibs/outlineForwarder}"
NDK_VERSION_PIN="27.2.12479018"
ANDROID_API="29"

PIN_FILE="${SCRIPT_DIR}/OUTLINE_SDK_COMMIT"
if [[ ! -f "${PIN_FILE}" ]]; then
    echo "ERROR: Missing ${PIN_FILE}" >&2
    exit 1
fi

PINNED_COMMIT="$(tr -d '[:space:]' < "${PIN_FILE}")"
if [[ ! "${PINNED_COMMIT}" =~ ^[0-9a-f]{40}$ ]]; then
    echo "ERROR: OUTLINE_SDK_COMMIT must be a 40-char hex commit SHA, got '${PINNED_COMMIT}'" >&2
    exit 1
fi
SHORT_COMMIT="${PINNED_COMMIT:0:12}"

resolve_ndk_dir() {
    if [[ -n "${ANDROID_NDK_HOME:-}" && -d "${ANDROID_NDK_HOME}" ]]; then
        echo "${ANDROID_NDK_HOME}"
        return 0
    fi
    local sdk_root="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
    if [[ -z "${sdk_root}" ]]; then
        echo "ERROR: ANDROID_NDK_HOME or ANDROID_HOME must be set" >&2
        return 1
    fi
    if [[ -d "${sdk_root}/ndk/${NDK_VERSION_PIN}" ]]; then
        echo "${sdk_root}/ndk/${NDK_VERSION_PIN}"
        return 0
    fi
    local latest
    latest="$(find "${sdk_root}/ndk" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort -V | tail -n 1 || true)"
    if [[ -n "${latest}" && -d "${latest}" ]]; then
        echo "${latest}"
        return 0
    fi
    echo "ERROR: Android NDK ${NDK_VERSION_PIN} not found under ${sdk_root}/ndk" >&2
    return 1
}

NDK_DIR="$(resolve_ndk_dir)"
HOST_OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
HOST_ARCH="$(uname -m)"
TOOLCHAIN_BIN="${NDK_DIR}/toolchains/llvm/prebuilt/${HOST_OS}-${HOST_ARCH}/bin"
if [[ ! -d "${TOOLCHAIN_BIN}" ]]; then
    echo "ERROR: NDK LLVM toolchain bin not found at ${TOOLCHAIN_BIN}" >&2
    exit 1
fi

pushd "${SCRIPT_DIR}" >/dev/null

export GOTOOLCHAIN=auto
MOD_VERSION="$(go list -m -f '{{.Version}}' golang.getoutline.org/sdk)"
if [[ "${MOD_VERSION}" != *"-${SHORT_COMMIT}" ]]; then
    echo "ERROR: go.mod version '${MOD_VERSION}' does not match OUTLINE_SDK_COMMIT '${PINNED_COMMIT}'" >&2
    exit 1
fi
go mod verify

build_abi() {
    local abi="$1"
    local goarch="$2"
    local clang_prefix="$3"
    local cc="${TOOLCHAIN_BIN}/${clang_prefix}${ANDROID_API}-clang"
    if [[ ! -x "${cc}" ]]; then
        echo "ERROR: Missing compiler ${cc}" >&2
        exit 1
    fi

    local abi_dir="${OUT_DIR}/${abi}"
    mkdir -p "${abi_dir}"
    local so_path="${abi_dir}/liboutline_forwarder.so"

    CGO_ENABLED=1 \
    GOOS=android \
    GOARCH="${goarch}" \
    CC="${cc}" \
    CGO_LDFLAGS="-Wl,-z,max-page-size=16384 -Wl,--build-id=none" \
    go build \
        -trimpath \
        -buildvcs=false \
        -buildmode=c-shared \
        -ldflags "-s -w -X main.pinnedOutlineCommit=${PINNED_COMMIT}" \
        -o "${so_path}" \
        .

    rm -f "${abi_dir}/liboutline_forwarder.h"
}

build_abi "arm64-v8a" "arm64" "aarch64-linux-android"
build_abi "x86_64" "amd64" "x86_64-linux-android"

popd >/dev/null
