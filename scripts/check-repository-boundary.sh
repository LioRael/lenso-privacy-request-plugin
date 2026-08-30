#!/usr/bin/env bash
set -euo pipefail

expected_crates=$'lenso-capability-privacy-request\nlenso-capability-privacy-request-admin\nlenso-capability-privacy-request-worker\nlenso-privacy-request-postgres-plugin'
actual_crates="$(find crates -mindepth 2 -maxdepth 2 -name Cargo.toml -print0 | xargs -0 sed -n 's/^name = "\([^"]*\)"/\1/p' | sort)"

if [[ "$actual_crates" != "$expected_crates" ]]; then
  echo "unexpected workspace crate boundary" >&2
  diff -u <(printf '%s\n' "$expected_crates") <(printf '%s\n' "$actual_crates") || true
  exit 1
fi

if rg -n 'path\s*=\s*"(\.\./\.\./|/)' --glob 'Cargo.toml' .; then
  echo "cross-repository or absolute path dependencies are not allowed" >&2
  exit 1
fi

if rg -n 'HashMap|Mutex<.*Vec|in.memory|memory fallback' crates --glob '*.rs'; then
  echo "ambient in-memory durable state is not allowed" >&2
  exit 1
fi

if rg -n 'lenso-platform-|lenso-module-|HostBuilder|HostLinkedModule|ModuleManifest' \
  Cargo.toml crates README.md docs --glob '!**/generated.rs'; then
  echo "legacy Lenso framework dependency or API found" >&2
  exit 1
fi

for capability in \
  'lenso.privacy-request@1' \
  'lenso.privacy-request-admin@1' \
  'lenso.privacy-request-worker@1' \
  'lenso.data-export-source@1' \
  'lenso.retention-participant@1' \
  'lenso.secrets@1' \
  'lenso.organization-membership@1' \
  'lenso.access-control@1'; do
  if ! rg -q "$capability" README.md docs crates; then
    echo "documented Capability boundary is missing: $capability" >&2
    exit 1
  fi
done

if sed -n '/#\[lenso::provides(/,/)]/p' \
  crates/lenso-privacy-request-postgres-plugin/src/lib.rs | \
  rg -q 'DataExportSource|RetentionParticipant'; then
  echo "Privacy Request must require, not falsely provide, data owner roles" >&2
  exit 1
fi
