#!/usr/bin/env bash

set -euo pipefail

readonly obsolete_kotlin_android_plugin='org\.jetbrains\.kotlin\.android'

if git grep --line-number --extended-regexp "$obsolete_kotlin_android_plugin" -- '*.gradle.kts'; then
    echo "AGP 9 provides built-in Kotlin support; remove the Kotlin Android plugin shown above." >&2
    exit 1
fi

echo "AGP built-in Kotlin configuration check passed."
