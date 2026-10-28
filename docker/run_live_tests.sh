#!/bin/bash
# Container entrypoint: start OVS (userspace), build and start the C++
# firewall daemon, start POX with the zone controller, then run a Mininet
# script from integration/ (the live test by default; see TEST_SCRIPT
# below). Exits with the script's status; dumps logs on failure.
set -euo pipefail

SRC=${SRC:-/src}
WORK=/work
POX=/opt/pox

rm -rf "$WORK" && cp -r "$SRC" "$WORK"
cp "$WORK"/controller.py "$WORK"/firewall_rules.py "$WORK"/firewall_client.py \
   "$WORK"/conntrack.py "$WORK"/policy.json "$WORK"/network.py "$WORK"/network.json \
   "$POX"/ext/

echo "*** Starting Open vSwitch (userspace datapath)"
mkdir -p /var/run/openvswitch
/usr/share/openvswitch/scripts/ovs-ctl --no-ovs-vswitchd start >/dev/null
ovs-vswitchd --pidfile --detach --log-file >/dev/null 2>&1

echo "*** Building and starting the C++ firewall daemon"
make -s -C "$WORK"/cpp
"$WORK"/cpp/firewall_daemon >/tmp/daemon.log 2>&1 </dev/null &

echo "*** Starting POX"
(cd "$POX" && exec python3 pox.py controller >/tmp/pox.log 2>&1 </dev/null) &

# Wait for POX to listen on the OpenFlow port before Mininet connects.
for _ in $(seq 50); do
    grep -q "is up" /tmp/pox.log 2>/dev/null && break
    sleep 0.2
done

# TEST_SCRIPT picks which script in integration/ to run (default: the
# live policy test; perf_test.py measures throughput and latency).
status=0
python3 "$WORK"/integration/"${TEST_SCRIPT:-live_test.py}" --datapath user "$@" || status=$?

if [ "$status" -ne 0 ]; then
    echo; echo "===== POX log ====="; cat /tmp/pox.log
    echo; echo "===== daemon log ====="; cat /tmp/daemon.log
fi
exit "$status"
