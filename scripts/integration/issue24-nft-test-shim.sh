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
batch_has_table_action() {
    python3 - "$1" "$2" <<'PY'
import json, pathlib, re, sys
path, action = pathlib.Path(sys.argv[1]), sys.argv[2]
text = path.read_text(encoding="utf-8")
try:
    document = json.loads(text)
except json.JSONDecodeError:
    raise SystemExit(0 if re.search(
        rf"(?m)^\s*{re.escape(action)}\s+table\s+inet\s+manyfw(?:\s|$)", text
    ) else 1)
def matches(value):
    if isinstance(value, dict):
        candidate = value.get(action)
        if isinstance(candidate, dict):
            for entity, details in candidate.items():
                if not isinstance(details, dict):
                    continue
                if entity == "table" and details.get("family") == "inet" \
                        and details.get("name") == "manyfw":
                    return True
                if details.get("family") == "inet" \
                        and (details.get("table") == "manyfw"
                             or details.get("name") == "manyfw"):
                    return True
        return any(matches(child) for child in value.values())
    if isinstance(value, list):
        return any(matches(child) for child in value)
    return False
raise SystemExit(0 if matches(document) else 1)
PY
}
batch_has_apply() {
    batch_has_table_action "$1" create || batch_has_table_action "$1" add
}
batch_has_flush() {
    python3 - "$1" <<'PY'
import json, pathlib, re, sys
text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
try:
    document = json.loads(text)
except json.JSONDecodeError:
    raise SystemExit(0 if re.search(r"(?m)^\s*flush(?:\s|$)", text) else 1)
def matches(value):
    if isinstance(value, dict):
        return "flush" in value or any(matches(child) for child in value.values())
    if isinstance(value, list):
        return any(matches(child) for child in value)
    return False
raise SystemExit(0 if matches(document) else 1)
PY
}
if [[ "$manyfw_caller" == yes && " $* " == *" flush "* ]]; then
    printf 'flush %s\n' "$*" >>/run/manyfw-issue24/manyfw-batches.log
    printf 'flush %s\n' "$*" >>/var/log/manyfw-issue24/production-batches.log
    printf 'issue24 test shim refused an nftables flush command\n' >&2
    exit 44
fi
batch_file=
for ((i = 1; i < $#; i++)); do
    if [[ "${!i}" == -f || "${!i}" == --file ]]; then
        next=$((i + 1))
        if [[ "${!next}" == - ]]; then batch_file=-; else batch_file=${!next}; fi
        break
    fi
done
if [[ -n "$batch_file" && "$batch_file" != - && -f "$batch_file" ]]; then
    cat "$batch_file" >>/run/manyfw-issue24/batches.log
    printf '\n' >>/run/manyfw-issue24/batches.log
    if [[ "$manyfw_caller" == yes ]]; then
        cat "$batch_file" >>/run/manyfw-issue24/manyfw-batches.log
        cat "$batch_file" >>/var/log/manyfw-issue24/production-batches.log
        printf '\n' >>/var/log/manyfw-issue24/production-batches.log
        printf '\n' >>/run/manyfw-issue24/manyfw-batches.log
    fi
    if [[ "$manyfw_caller" == yes ]] \
        && batch_has_flush "$batch_file"; then
        printf 'issue24 test shim refused an nftables flush command\n' >&2
        exit 44
    fi
fi
if [[ "$batch_file" == - ]]; then
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
        && batch_has_flush "$batch"; then
        printf 'issue24 test shim refused an nftables flush command\n' >&2
        exit 44
    fi
    if batch_has_apply "$batch" \
        && [[ -e /run/manyfw-issue24/delay-apply ]]; then
        sleep 8
    fi
    if batch_has_apply "$batch" \
        && [[ -e /run/manyfw-issue24/pause-verification ]]; then
        # Arm a state-aware pause; the first table read after the durable state
        # becomes Verifying is the real backend verification boundary.
        touch /run/manyfw-issue24/pause-verification-armed
        rm -f /run/manyfw-issue24/pause-verification
    fi
    if batch_has_apply "$batch" \
        && [[ -e /run/manyfw-issue24/truncate-apply ]]; then
        truncated=$(mktemp /run/manyfw-issue24/nft-truncated.XXXXXX)
        trap 'rm -f -- "$batch" "$truncated"' EXIT
        size=$(stat -c %s "$batch")
        head -c "$((size / 2))" "$batch" >"$truncated"
        real_args=()
        replace_next=no
        for arg in "$@"; do
            if [[ "$replace_next" == yes ]]; then
                real_args+=("$truncated")
                replace_next=no
            else
                real_args+=("$arg")
                [[ "$arg" == -f || "$arg" == --file ]] && replace_next=yes
            fi
        done
        if "$real_nft" "${real_args[@]}"; then
            exit 46
        else
            result=$?
            exit "$result"
        fi
    fi
    if batch_has_table_action "$batch" delete \
        && [[ -e /run/manyfw-issue24/fail-rollback ]]; then
        exit 43
    fi
    real_args=()
    replace_next=no
    for arg in "$@"; do
        if [[ "$replace_next" == yes ]]; then
            real_args+=("$batch")
            replace_next=no
        else
            real_args+=("$arg")
            [[ "$arg" == -f || "$arg" == --file ]] && replace_next=yes
        fi
    done
    "$real_nft" "${real_args[@]}"
    result=$?
    if batch_has_apply "$batch" \
        && [[ $result -eq 0 && -e /run/manyfw-issue24/pause-after-commit ]]; then
        touch /run/manyfw-issue24/apply-committed
        while [[ -e /run/manyfw-issue24/hold-after-commit ]]; do sleep 0.1; done
    fi
    if batch_has_table_action "$batch" delete \
        && [[ $result -eq 0 && -e /run/manyfw-issue24/fail-after-rollback-commit ]]; then
        exit 45
    fi
    if batch_has_apply "$batch" \
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
