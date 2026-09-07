#!/bin/bash
# deploy.sh: push the nodeguard artifact set to one host and verify it,
# WITHOUT enabling or starting anything. Run from the repo root:
#   bash deploy/deploy.sh <ssh-target> <host-config-dir>
# e.g.
#   bash deploy/deploy.sh admin@gateway.example.net /path/to/private/hosts/gateway
# The host config dir holds the per-host files (see hosts/example-gateway).
# Real deployments keep those dirs OUTSIDE this repo; never commit real
# addresses, interface names, or network layout to a public tree.
# Bring-up is deliberately manual and phased; see docs/design.md.
set -euo pipefail

SSH="${1:?usage: deploy.sh <ssh-target> <host-config-dir> [--with-kernel]}"
HOSTDIR="${2:?usage: deploy.sh <ssh-target> <host-config-dir> [--with-kernel]}"
WITH_KERNEL=0
for arg in "${@:3}"; do
    case "$arg" in
    --with-kernel) WITH_KERNEL=1 ;;
    *)
        echo "unknown argument: $arg" >&2
        echo "usage: deploy.sh <ssh-target> <host-config-dir> [--with-kernel]" >&2
        exit 2
        ;;
    esac
done
REPO="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$REPO/build/out"

[ -d "$HOSTDIR" ] || { echo "no such host config dir: $HOSTDIR"; exit 2; }
for f in nodeguard.env allow4.txt allow6.txt responder.conf feeds.conf \
         sysconfig-suricata suricata-50-limits.conf \
         nodeguard-xdp-10-device.conf suricata.yaml; do
    [ -f "$HOSTDIR/$f" ] || { echo "missing $HOSTDIR/$f (suricata.yaml comes from build.sh)"; exit 2; }
done
# SAFETY (ADR 0007): the datapath object never ships as a stowaway of a
# userspace deploy; a restart during a multi-day phase must reload the
# OLD object. Kernel artifacts move only with --with-kernel.
EXPECTED_KERN_SHA=""
if [ "$WITH_KERNEL" -eq 1 ]; then
    [ -f "$OUT/nodeguard_kern.o" ] || { echo "run build/build.sh first"; exit 2; }
    [ -f "$OUT/nodeguard-maps.spec" ] || { echo "spec missing; run build/build.sh"; exit 2; }
    [ -f "$OUT/nodeguard_kern.o.sha256" ] || { echo "hash record missing; run build/build.sh"; exit 2; }
    # SAFETY (ADR 0004): the emitted sha256 is the object's pairing
    # evidence, so it is compared, not printed for a human to eyeball. The
    # scenario this catches is a stale build/out (an object and a hash
    # written by different build runs, or an object rebuilt under another
    # checkout), not a truncated copy: set -e aborts that first.
    EXPECTED_KERN_SHA=$(awk 'NR == 1 { print $1 }' "$OUT/nodeguard_kern.o.sha256")
    local_sha=$(sha256sum "$OUT/nodeguard_kern.o" | awk '{print $1}')
    if [ "$local_sha" != "$EXPECTED_KERN_SHA" ]; then
        echo "kernel object does not match its recorded sha256:"
        echo "  object   $local_sha"
        echo "  recorded $EXPECTED_KERN_SHA ($OUT/nodeguard_kern.o.sha256)"
        echo "rebuild with build/build.sh; nothing was staged"
        exit 2
    fi
fi

STAGE=/tmp/nodeguard-deploy
echo "== staging to $SSH:$STAGE =="
# shellcheck disable=SC2029
ssh "$SSH" "rm -rf $STAGE && mkdir -p $STAGE"
KERNEL_FILES=""
if [ "$WITH_KERNEL" -eq 1 ]; then
    KERNEL_FILES="$OUT/nodeguard_kern.o $OUT/nodeguard-maps.spec $OUT/nodeguard_kern.o.sha256"
fi
# shellcheck disable=SC2086
scp -q $KERNEL_FILES \
    "$REPO"/bin/ngmap.py "$REPO"/bin/nodeguard-lib.sh \
    "$REPO"/bin/nodeguard-maps "$REPO"/bin/nodeguard-attach \
    "$REPO"/bin/nodeguard-detach "$REPO"/bin/nodeguard-cli \
    "$REPO"/bin/nodeguard-status "$REPO"/bin/nodeguard-reload \
    "$REPO"/bin/nodeguard-watchdog "$REPO"/bin/nodeguard-canary \
    "$REPO"/bin/nodeguard-responder "$REPO"/bin/nodeguard-feeds \
    "$REPO"/bin/nodeguard-geo \
    "$REPO"/units/*.service "$REPO"/units/*.timer \
    "$REPO"/etc/protected.conf "$REPO"/etc/sids.conf \
    "$REPO"/etc/tmpfiles-nodeguard.conf "$REPO"/etc/logrotate-suricata.conf \
    "$REPO"/etc/zabbix-userparameter-nodeguard.conf \
    "$REPO"/build/suricata-stock.version \
    "$HOSTDIR"/nodeguard.env "$HOSTDIR"/allow4.txt "$HOSTDIR"/allow6.txt \
    "$HOSTDIR"/responder.conf "$HOSTDIR"/feeds.conf \
    "$HOSTDIR"/sysconfig-suricata \
    "$HOSTDIR"/suricata-50-limits.conf "$HOSTDIR"/nodeguard-xdp-10-device.conf \
    "$HOSTDIR"/suricata.yaml \
    "$SSH:$STAGE/"

echo "== verifying, then installing (no unit is enabled or started) =="
# The expected object hash is passed as an argument rather than
# interpolated, so the heredoc stays quoted and nothing else expands here.
# shellcheck disable=SC2029
ssh "$SSH" sudo /bin/bash -s -- "$EXPECTED_KERN_SHA" <<'REMOTE'
set -euo pipefail
S=/tmp/nodeguard-deploy
EXPECTED_KERN_SHA="${1:-}"
# The ruleset suricata -T needs: build/suricata-stock.yaml's
# default-rule-path joined with its single rule-files entry, which is the
# file suricata-update writes. Nothing in the suricata RPM creates it.
SURICATA_RULES=/var/lib/suricata/rules/suricata.rules

# Preflight: deploy is phase 0 AFTER package install; failing early keeps
# a run from half-installing.
[ -d /etc/suricata ] || { echo "ERROR: /etc/suricata missing; install the suricata RPM first (phase 0: dnf install suricata), then re-run deploy.sh" >&2; exit 3; }

# INVARIANT: ONE staged unit list feeds both the verification loop and the
# install command below, so the set verified and the set installed cannot
# diverge. A second, hand-maintained list is exactly how nodeguard-geo's
# timer shipped with no nodeguard-geo binary behind it.
units=()
for u in "$S"/*.service "$S"/*.timer; do
    [ -e "$u" ] || continue
    units+=("$u")
done
[ "${#units[@]}" -gt 0 ] || { echo "ERROR: no unit files staged" >&2; exit 3; }

# The per-host drop-in is the ONE unit fragment that differs per host, so
# it is the one most worth verifying; systemd merges drop-ins from a
# <unit>.d directory beside the unit file, and a flat file named
# nodeguard-xdp-10-device.conf is merged with nothing. Moving it into
# place inside the staging directory is what puts it in front of
# systemd-analyze; this rearranges $S only and touches no host path.
mkdir -p "$S/nodeguard-xdp.service.d"
cp "$S/nodeguard-xdp-10-device.conf" "$S/nodeguard-xdp.service.d/10-device.conf"

# The executables this run installs into /usr/local/sbin, split by what
# checks them. Same lists drive the syntax checks and the install loop.
sbin_shell=(nodeguard-maps nodeguard-attach nodeguard-detach nodeguard-cli
            nodeguard-status nodeguard-reload nodeguard-watchdog
            nodeguard-canary)
sbin_python=(nodeguard-responder nodeguard-feeds nodeguard-geo)

# Drop exactly one class of systemd-analyze diagnostic: an ExecStart or
# ExecStop binary that this run stages and installs a few lines below.
# Verification runs BEFORE installation, so on a first deploy those paths
# do not exist yet and on an upgrade the file on disk is still the old
# one; either way the staged executable is the one being shipped, and it
# is syntax-checked separately. Any other diagnostic still fails.
staged_executable_diag() {
    local line="$1" path
    case "$line" in
    *"is not executable"*)
        path=$(printf '%s\n' "$line" \
            | sed -n 's/.*Command \(\/[^ ]*\) is not executable.*/\1/p')
        # A matching basename is not enough: a unit naming a path this run
        # never installs must still fail, even when a file of that name
        # happens to be staged. Only the two destinations the install loop
        # below writes to qualify.
        case "$path" in
        /usr/local/sbin/* | /usr/local/lib/nodeguard/*) ;;
        *) return 1 ;;
        esac
        [ -f "$S/$(basename "$path")" ]
        ;;
    *) return 1 ;;
    esac
}

echo "-- verification (staged copies; nothing installed yet) --"
verify_fail=0
for f in "${sbin_shell[@]}" nodeguard-lib.sh; do
    bash -n "$S/$f"
done
py_files=("$S/ngmap.py")
for f in "${sbin_python[@]}"; do
    py_files+=("$S/$f")
done
python3 -m py_compile "${py_files[@]}"
for u in "${units[@]}"; do
    out=""
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        case "$line" in *"Unit is bound"*) continue ;; esac
        staged_executable_diag "$line" && continue
        out+="$line"$'\n'
    done < <(systemd-analyze verify "$u" 2>&1)
    if [ -n "$out" ]; then
        echo "UNIT VERIFY FAILED: $(basename "$u")"
        printf '%s' "$out"
        verify_fail=1
    fi
done
if [ -f "$S/nodeguard_kern.o" ]; then
    staged_sha=$(sha256sum "$S/nodeguard_kern.o" | awk '{print $1}')
    if [ -z "$EXPECTED_KERN_SHA" ]; then
        echo "kernel object staged with no expected hash to compare against"
        verify_fail=1
    elif [ "$staged_sha" != "$EXPECTED_KERN_SHA" ]; then
        echo "staged kernel object hash mismatch: $staged_sha != $EXPECTED_KERN_SHA"
        verify_fail=1
    fi
fi
grep -q '^UserParameter=nodeguard.kv.raw,' "$S/zabbix-userparameter-nodeguard.conf" \
    || { echo "zabbix agent conf missing nodeguard.kv.raw"; verify_fail=1; }
grep -q '/var/log/suricata/\*.json' "$S/logrotate-suricata.conf" || { echo "logrotate config missing eve.json coverage"; verify_fail=1; }
grep -vE '^[[:space:]]*#' "$S/logrotate-suricata.conf" | grep -q copytruncate && { echo "logrotate config uses copytruncate (loses lines)"; verify_fail=1; }
# The generated config is only validated if suricata itself accepts it;
# mkyaml.py has promised this check since it was written and nothing ran
# it. suricata -T forces engine.init-failure-fatal, so a missing ruleset
# is fatal to it as well; on a phase-0 host (packages installed,
# suricata-update not yet run: docs/design.md section 6.4) that would
# abort the bootstrap deploy this whole reorder exists to keep working.
# The ruleset therefore gates the check instead of the check gating the
# deploy, and a skipped validation is reported as unvalidated, not passed.
if [ -f "$SURICATA_RULES" ]; then
    if ! suricata_test=$(suricata -T -c "$S/suricata.yaml" 2>&1); then
        echo "suricata -T rejected the staged suricata.yaml:"
        printf '%s\n' "$suricata_test"
        verify_fail=1
    fi
else
    echo "WARNING: $SURICATA_RULES absent, so the staged suricata.yaml is UNVALIDATED (suricata -T skipped); this is the phase-0 bootstrap state, and a re-run after suricata-update (phase 1) validates it"
fi
# Stock drift: the generated header names the RPM the stock yaml was
# captured from, and a host that has moved past it may be running a
# config schema the generator has never seen. The query is arch-free
# because plain rpm -q prints the NVRA, which would warn on every deploy
# and train the operator to ignore the warning.
if [ -f "$S/suricata-stock.version" ]; then
    stock_ver=$(head -1 "$S/suricata-stock.version")
else
    stock_ver=""
fi
host_ver=$(rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}' suricata 2>/dev/null || echo unknown)
if [ -z "$stock_ver" ]; then
    echo "stock version sidecar missing from the staged artifacts"
    verify_fail=1
elif [ "$host_ver" != "$stock_ver" ]; then
    echo "WARNING: suricata stock drift: host has $host_ver, the generated config was captured from $stock_ver; refresh build/suricata-stock.yaml and its .version sidecar"
fi
if [ -e /etc/suricata/suricata.yaml.rpmnew ]; then
    echo "WARNING: /etc/suricata/suricata.yaml.rpmnew exists; the RPM shipped a config schema the generated file has not been reconciled against"
fi
[ "$verify_fail" -eq 0 ] || { echo "deploy verification FAILED; host untouched"; exit 4; }

echo "-- installing --"
install -d -m 0755 /usr/local/lib/nodeguard /etc/nodeguard /var/lib/nodeguard /var/lib/nodeguard/feeds
if [ -f "$S/nodeguard_kern.o" ]; then
    # keep the N-1 object AND spec for hitless rollback, but only rotate
    # when the staged pair actually differs: an idempotent re-run must
    # never overwrite the rollback target with the file it rolls back
    # FROM. The decision is taken ONCE over both artifacts, because a
    # per-artifact guard rotates the changed one and leaves the other at
    # an older generation, and the straddled pair it restores fails the
    # spec-object pairing check.
    rotate=0
    for artifact in nodeguard_kern.o nodeguard-maps.spec; do
        cur="/usr/local/lib/nodeguard/$artifact"
        [ -f "$cur" ] || continue
        cmp -s "$S/$artifact" "$cur" || rotate=1
    done
    if [ "$rotate" -eq 1 ]; then
        for artifact in nodeguard_kern.o nodeguard-maps.spec; do
            cur="/usr/local/lib/nodeguard/$artifact"
            if [ -f "$cur" ]; then
                cp -p "$cur" "$cur.prev"
            fi
        done
    fi
    install -m 0644 "$S/nodeguard_kern.o" "$S/nodeguard-maps.spec" \
        "$S/nodeguard_kern.o.sha256" /usr/local/lib/nodeguard/
fi
install -m 0755 "$S/ngmap.py" /usr/local/lib/nodeguard/
install -m 0644 "$S/nodeguard-lib.sh" /usr/local/lib/nodeguard/

for f in "${sbin_shell[@]}" "${sbin_python[@]}"; do
    install -m 0755 "$S/$f" /usr/local/sbin/
done
for name in block unblock list flush off on; do
    ln -sf nodeguard-cli "/usr/local/sbin/nodeguard-$name"
done

install -m 0644 "$S/nodeguard.env" "$S/allow4.txt" "$S/allow6.txt" \
    "$S/responder.conf" "$S/feeds.conf" "$S/protected.conf" "$S/sids.conf" /etc/nodeguard/

install -m 0644 "${units[@]}" /etc/systemd/system/
install -d /etc/systemd/system/nodeguard-xdp.service.d
# The copy under the staged .d directory is the one systemd-analyze
# merged and verified above; installing that exact file keeps verified
# and installed the same bytes.
install -m 0644 "$S/nodeguard-xdp.service.d/10-device.conf" \
    /etc/systemd/system/nodeguard-xdp.service.d/10-device.conf
install -d /etc/systemd/system/suricata.service.d
install -m 0644 "$S/suricata-50-limits.conf" \
    /etc/systemd/system/suricata.service.d/50-limits.conf
install -m 0644 "$S/tmpfiles-nodeguard.conf" /etc/tmpfiles.d/nodeguard.conf
install -d /etc/zabbix_agentd.d
install -m 0644 "$S/zabbix-userparameter-nodeguard.conf" /etc/zabbix_agentd.d/nodeguard.conf
# NOTE: this fleet's agent reads /etc/zabbix_agentd.conf (Fedora ships no
# include dir); deploy owns the Include line so the conf actually loads.
if [ -f /etc/zabbix_agentd.conf ] && \
        ! grep -q '^Include=/etc/zabbix_agentd.d/' /etc/zabbix_agentd.conf; then
    echo 'Include=/etc/zabbix_agentd.d/*.conf' >> /etc/zabbix_agentd.conf
fi
# NOTE: agent restart is a deliberate runbook step, not automated here.
systemd-tmpfiles --create /etc/tmpfiles.d/nodeguard.conf

install -m 0644 "$S/sysconfig-suricata" /etc/sysconfig/suricata
install -m 0640 -o suricata -g suricata "$S/suricata.yaml" /etc/suricata/suricata.yaml

# [18] Own eve.json rotation: replace whatever /etc/logrotate.d/suricata
# holds (stale pre-RPM configs silently win otherwise; verified on a
# live target) and clear any .rpmnew the RPM left.
install -m 0644 "$S/logrotate-suricata.conf" /etc/logrotate.d/suricata
rm -f /etc/logrotate.d/suricata.rpmnew

restorecon -Rv /usr/local/lib/nodeguard /usr/local/sbin /etc/nodeguard \
    /etc/systemd/system /etc/sysconfig/suricata 2>/dev/null | grep -v '^$' || true
systemctl daemon-reload

if [ -f "$S/nodeguard_kern.o" ]; then
    echo "kernel object matches its build record: $EXPECTED_KERN_SHA"
fi
rm -rf "$S"
echo "deploy OK: files installed, nothing enabled or started"
REMOTE
