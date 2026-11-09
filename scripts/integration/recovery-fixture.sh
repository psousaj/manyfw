#!/usr/bin/env bash
# Test-only firewall mutation/recovery fixture. Install and execute only inside
# a harness-owned disposable KVM guest; this is not a ManyFW backend.
set -Eeuo pipefail

STATE_DIR=/var/lib/manyfw-recovery-fixture
STATE_FILE=$STATE_DIR/armed
UNIT_DIR=/etc/systemd/system
FIXTURE=/usr/local/sbin/manyfw-recovery-fixture

fail() { printf 'recovery fixture: %s\n' "$*" >&2; exit 1; }

backend_state() {
    case "$1" in
        nft)
            if nft list table inet manyfw_recovery_test >/dev/null 2>&1; then
                nft -s list table inet manyfw_recovery_test
            else
                printf 'inet manyfw_recovery_test:absent\n'
            fi
            ;;
        iptables)
            {
                for command in iptables ip6tables; do
                    if "$command" -S MFW_RECOVERY_TEST >/dev/null 2>&1; then
                        printf '%s:chain-present\n' "$command"
                        "$command" -S MFW_RECOVERY_TEST
                        if "$command" -C INPUT -j MFW_RECOVERY_TEST >/dev/null 2>&1; then
                            printf '%s:jump-present\n' "$command"
                        else
                            printf '%s:jump-absent\n' "$command"
                        fi
                    else
                        printf '%s:chain-absent\n' "$command"
                    fi
                done
            }
            ;;
        *) fail "unknown backend: $1" ;;
    esac
}

restore_owned_scope() {
    local backend=$1
    case "$backend" in
        nft)
            if nft list table inet manyfw_recovery_test >/dev/null 2>&1; then
                nft delete table inet manyfw_recovery_test
            fi
            ;;
        iptables)
            local command
            for command in iptables ip6tables; do
                if "$command" -S MFW_RECOVERY_TEST >/dev/null 2>&1; then
                    while "$command" -C INPUT -j MFW_RECOVERY_TEST >/dev/null 2>&1; do
                        "$command" -D INPUT -j MFW_RECOVERY_TEST
                    done
                    "$command" -F MFW_RECOVERY_TEST
                    "$command" -X MFW_RECOVERY_TEST
                fi
                if [[ "$command" == iptables && -e "$STATE_DIR/fail-partial-restore-once" ]]; then
                    rm -f -- "$STATE_DIR/fail-partial-restore-once"
                    printf 'partial rollback injected after IPv4 cleanup\n' \
                        >"$STATE_DIR/rollback-interrupted.iptables"
                    backend_state iptables >>"$STATE_DIR/rollback-interrupted.iptables" || true
                    printf 'deliberate partial rollback interruption\n' >>"$STATE_DIR/recovery-attempts"
                    return 1
                fi
            done
            ;;
        *) fail "unknown backend in recovery state: $backend" ;;
    esac
}

recover_if_due() {
    [[ -r "$STATE_FILE" ]] || exit 0
    local backend original_boot deadline current_boot now
    read -r backend original_boot deadline <"$STATE_FILE"
    current_boot=$(cat /proc/sys/kernel/random/boot_id)
    now=$(date +%s)
    if [[ "$current_boot" != "$original_boot" || "$now" -ge "$deadline" ]]; then
        printf 'recovery attempt boot=%s\n' "$current_boot" >>"$STATE_DIR/recovery-attempts"
        if [[ -e "$STATE_DIR/kill-recovery-once" ]]; then
            rm -f -- "$STATE_DIR/kill-recovery-once"
            kill -KILL "$$"
        fi
        restore_owned_scope "$backend"
        printf 'recovered backend=%s boot_changed=%s deadline_reached=%s\n' \
            "$backend" "$([[ "$current_boot" != "$original_boot" ]] && echo true || echo false)" \
            "$([[ "$now" -ge "$deadline" ]] && echo true || echo false)" \
            >>"$STATE_DIR/recovery.log"
        rm -f -- "$STATE_FILE"
    fi
}

install_recovery_timer() {
    install -d -m 0700 "$STATE_DIR"
    cat >"$UNIT_DIR/manyfw-recovery-fixture.service" <<EOF
[Unit]
Description=Disposable ManyFW recovery fixture (test-only)

[Service]
Type=oneshot
ExecStart=$FIXTURE recover
EOF
    cat >"$UNIT_DIR/manyfw-recovery-fixture.timer" <<'EOF'
[Unit]
Description=Poll disposable recovery fixture state (test-only)

[Timer]
OnBootSec=1s
OnUnitActiveSec=1s
AccuracySec=100ms
Unit=manyfw-recovery-fixture.service

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now manyfw-recovery-fixture.timer
}

arm() {
    local backend=$1 deadline_seconds=${2:-12} fault=${3:-} current_boot now temporary
    [[ "$deadline_seconds" =~ ^[0-9]+$ ]] || fail 'deadline must be a non-negative integer'
    [[ ! -e "$STATE_FILE" ]] || fail 'a recovery transaction is already armed'
    case "$backend" in
        nft)
            nft list table inet manyfw_recovery_test >/dev/null 2>&1 \
                && fail 'test-owned nftables table already exists'
            ;;
        iptables)
            for command in iptables ip6tables; do
                "$command" -S MFW_RECOVERY_TEST >/dev/null 2>&1 \
                    && fail "test-owned chain already exists in $command"
                "$command" -C INPUT -j MFW_RECOVERY_TEST >/dev/null 2>&1 \
                    && fail "test-owned jump already exists in $command"
            done
            ;;
        *) fail "unknown backend: $backend" ;;
    esac
    now=$(date +%s)
    current_boot=$(cat /proc/sys/kernel/random/boot_id)
    temporary="$STATE_FILE.tmp.$$"
    printf '%s %s %s\n' "$backend" "$current_boot" "$((now + deadline_seconds))" >"$temporary"
    chmod 0600 "$temporary"
    mv -f -- "$temporary" "$STATE_FILE"
    case "$fault" in
        '') ;;
        kill-recovery-once) : >"$STATE_DIR/kill-recovery-once" ;;
        partial-rollback-once) : >"$STATE_DIR/fail-partial-restore-once" ;;
        *) fail "unknown recovery fault injection: $fault" ;;
    esac
    backend_state "$backend" >"$STATE_DIR/before.$backend"
}

apply_block() {
    local backend=$1 behavior=$2
    [[ -r "$STATE_FILE" ]] || fail 'recovery was not armed before mutation'
    printf '%s %s\n' "$backend" "$behavior" >"$STATE_DIR/apply-started"
    case "$backend" in
        nft)
            nft add table inet manyfw_recovery_test
            nft add chain inet manyfw_recovery_test input '{ type filter hook input priority -500; policy accept; }'
            nft add rule inet manyfw_recovery_test input meta nfproto ipv4 tcp dport 22 drop
            if [[ "$behavior" == fail ]]; then
                # Deliberately fail after the IPv4 half of the dual-stack
                # mutation; recovery must remove only the fixture-owned table.
                backend_state "$backend" >"$STATE_DIR/after.$backend"
                nft add rule inet manyfw_recovery_test input this-is-not-a-valid-expression
                fail 'invalid nft operation unexpectedly succeeded'
            fi
            nft add rule inet manyfw_recovery_test input meta nfproto ipv6 tcp dport 22 drop
            ;;
        iptables)
            iptables -N MFW_RECOVERY_TEST
            iptables -I INPUT 1 -j MFW_RECOVERY_TEST
            iptables -A MFW_RECOVERY_TEST -p tcp --dport 22 -j DROP
            if [[ "$behavior" == fail ]]; then
                backend_state "$backend" >"$STATE_DIR/after.$backend"
                iptables -A MFW_RECOVERY_TEST --manyfw-deliberate-failure
                fail 'invalid iptables operation unexpectedly succeeded'
            fi
            ip6tables -N MFW_RECOVERY_TEST
            ip6tables -I INPUT 1 -j MFW_RECOVERY_TEST
            ip6tables -A MFW_RECOVERY_TEST -p tcp --dport 22 -j DROP
            ;;
        *) fail "unknown backend: $backend" ;;
    esac
    backend_state "$backend" >"$STATE_DIR/after.$backend"
    case "$behavior" in
        sleep) sleep 120 ;;
        kill)
            printf 'killed-before-completion\n' >"$STATE_DIR/apply-interrupted"
            kill -KILL "$$"
            ;;
        complete) exit 0 ;;
        fail) fail 'deliberate apply failure did not fail' ;;
        *) fail "unknown apply behavior: $behavior" ;;
    esac
}

case "${1:-}" in
    install) install_recovery_timer ;;
    arm) arm "${2:?backend required}" "${3:-12}" "${4:-}" ;;
    apply) apply_block "${2:?backend required}" "${3:?behavior required}" ;;
    recover) recover_if_due ;;
    state)
        backend_state "${2:?backend required}"
        ;;
    *) fail 'usage: recovery-fixture.sh install|arm <nft|iptables> [seconds]|apply <nft|iptables> <sleep|kill|fail|complete>|recover|state <nft|iptables>' ;;
esac
