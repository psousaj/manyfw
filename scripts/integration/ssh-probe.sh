#!/usr/bin/env bash

ssh_probe_is_expected_timeout() {
    local probe_output=$1
    probe_output=${probe_output//$'\r\n'/$'\n'}
    probe_output=${probe_output%$'\r'}
    [[ "$probe_output" == $'SSH_PROBE_STATUS=255\n'* ]] \
        && grep -Eq \
            '^(ssh: )?connect to host .* port [0-9]+: Connection timed out$|^Connection timed out( during banner exchange)?$|^Connection to .* port [0-9]+ timed out$' \
            <<<"$probe_output"
}

# This only authorizes another attempt. It is never SSH-loss evidence.
ssh_probe_is_outer_timeout() {
    local process_status=$1 probe_output=$2
    probe_output=${probe_output//$'\r\n'/$'\n'}
    probe_output=${probe_output%$'\r'}
    [[ "$process_status" == 124 \
        && ( "$probe_output" == 'SSH_PROBE_STATUS=124' \
            || "$probe_output" == $'SSH_PROBE_STATUS=124\n'* ) ]]
}

# Retry commands that return status 255. SSH may also return 255 when the
# remote command exits 255, so callers MUST pass only idempotent operations.
ssh_retry_status_255() {
    local max_attempts=$1 attempt status
    shift
    [[ "$max_attempts" =~ ^[1-9][0-9]*$ && $# -gt 0 ]] || return 2
    for ((attempt = 1; attempt <= max_attempts; attempt++)); do
        if "$@"; then
            return 0
        else
            status=$?
        fi
        [[ "$status" == 255 ]] || return "$status"
        [[ "$attempt" == "$max_attempts" ]] || sleep 0.5
    done
    return 255
}
