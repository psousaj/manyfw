#!/usr/bin/env bash
# Test-only fault injector. It forwards every request to the real nft binary;
# selected batch operations are delayed or report an ambiguous post-commit error.
set -euo pipefail
real_nft=/usr/sbin/nft
mkdir -p /run/manyfw-issue24
install -d -m 0700 /var/log/manyfw-issue24
touch /run/manyfw-issue24/batches.log
touch /run/manyfw-issue24/manyfw-batches.log
chmod 0600 /run/manyfw-issue24/batches.log
chmod 0600 /run/manyfw-issue24/manyfw-batches.log
caller_cmd=$(tr '\0' ' ' </proc/"$PPID"/cmdline 2>/dev/null || true)
manyfw_caller=no
[[ "$caller_cmd" == *manyfw* ]] && manyfw_caller=yes
if [[ "$manyfw_caller" == yes && " $* " == *" flush "* ]]; then
    printf 'flush %s\n' "$*" >>/run/manyfw-issue24/manyfw-batches.log
    printf 'flush %s\n' "$*" >>/var/log/manyfw-issue24/production-batches.log
    printf 'issue24 test shim refused an nftables flush command\n' >&2
    exit 44
fi
if [[ "${1:-}" == -f && "${2:-}" != - && -f "${2:-}" ]]; then
    cat "$2" >>/run/manyfw-issue24/batches.log
    printf '\n' >>/run/manyfw-issue24/batches.log
    if [[ "$manyfw_caller" == yes ]]; then
        cat "$2" >>/run/manyfw-issue24/manyfw-batches.log
        cat "$2" >>/var/log/manyfw-issue24/production-batches.log
        printf '\n' >>/var/log/manyfw-issue24/production-batches.log
        printf '\n' >>/run/manyfw-issue24/manyfw-batches.log
    fi
    if [[ "$manyfw_caller" == yes ]] \
        && grep -Eq '^[[:space:]]*flush([[:space:]]|$)' "$2"; then
        printf 'issue24 test shim refused an nftables flush command\n' >&2
        exit 44
    fi
fi
if [[ "${1:-}" == -f && "${2:-}" == - ]]; then
    batch=$(mktemp /run/manyfw-issue24/nft-batch.XXXXXX)
    trap 'rm -f -- "$batch"' EXIT
    cat >"$batch"
    cat "$batch" >>/run/manyfw-issue24/batches.log
    printf '\n' >>/run/manyfw-issue24/batches.log
    if [[ "$manyfw_caller" == yes ]]; then
        cat "$batch" >>/run/manyfw-issue24/manyfw-batches.log
        cat "$batch" >>/var/log/manyfw-issue24/production-batches.log
        printf '\n' >>/var/log/manyfw-issue24/production-batches.log
        printf '\n' >>/run/manyfw-issue24/manyfw-batches.log
    fi
    if [[ "$manyfw_caller" == yes ]] \
        && grep -Eq '^[[:space:]]*flush([[:space:]]|$)' "$batch"; then
        printf 'issue24 test shim refused an nftables flush command\n' >&2
        exit 44
    fi
    if grep -q 'add table inet manyfw' "$batch" \
        && [[ -e /run/manyfw-issue24/delay-apply ]]; then
        sleep 8
    fi
    if grep -q 'add table inet manyfw' "$batch" \
        && [[ -e /run/manyfw-issue24/pause-verification ]]; then
        # Arm a state-aware pause; the first table read after the durable state
        # becomes Verifying is the real backend verification boundary.
        touch /run/manyfw-issue24/pause-verification-armed
        rm -f /run/manyfw-issue24/pause-verification
    fi
    if grep -q 'add table inet manyfw' "$batch" \
        && [[ -e /run/manyfw-issue24/truncate-apply ]]; then
        truncated=$(mktemp /run/manyfw-issue24/nft-truncated.XXXXXX)
        trap 'rm -f -- "$batch" "$truncated"' EXIT
        size=$(stat -c %s "$batch")
        head -c "$((size / 2))" "$batch" >"$truncated"
        if "$real_nft" -f "$truncated"; then
            exit 46
        else
            result=$?
            exit "$result"
        fi
    fi
    if grep -q 'delete table inet manyfw' "$batch" \
        && [[ -e /run/manyfw-issue24/fail-rollback ]]; then
        exit 43
    fi
    "$real_nft" -f "$batch"
    result=$?
    if grep -q 'add table inet manyfw' "$batch" \
        && [[ $result -eq 0 && -e /run/manyfw-issue24/pause-after-commit ]]; then
        touch /run/manyfw-issue24/apply-committed
        while [[ -e /run/manyfw-issue24/hold-after-commit ]]; do sleep 0.1; done
    fi
    if grep -q 'delete table inet manyfw' "$batch" \
        && [[ $result -eq 0 && -e /run/manyfw-issue24/fail-after-rollback-commit ]]; then
        exit 45
    fi
    if grep -q 'add table inet manyfw' "$batch" \
        && [[ $result -eq 0 && -e /run/manyfw-issue24/fail-after-commit ]]; then
        exit 42
    fi
    exit "$result"
fi
if [[ -e /run/manyfw-issue24/pause-verification-armed \
    && " $* " == *" list table inet manyfw "* ]]; then
    if python3 - <<'PY'
import glob, json
for path in glob.glob('/var/lib/manyfw/transactions/*.json'):
    try:
        with open(path, encoding='utf-8') as source:
            if json.load(source).get('state', '').lower() == 'verifying':
                raise SystemExit(0)
    except (OSError, ValueError):
        continue
raise SystemExit(1)
PY
    then
        rm -f /run/manyfw-issue24/pause-verification-armed
        sleep 45
    fi
fi
exec "$real_nft" "$@"
