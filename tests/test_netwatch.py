"""Netwatch probe sensor tests (0.17.5): widened service ports,
scan-shape detection over sampler history, canary hits.
Run: python3 tests/test_netwatch.py (or pytest tests/test_netwatch.py)"""
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from aishield import netwatch as nw


def _ts(offset_s=0):
    return time.strftime("%Y-%m-%d %H:%M:%S",
                         time.localtime(time.time() - offset_s))


def test_live_snapshot_sees_service_ports():
    # netstat (mac-style addr.port); 22/443 are watched services,
    # 9999 is not
    out = ("tcp4  0  0  192.0.2.1.22  203.0.113.9.51000  "
           "ESTABLISHED\n"
           "tcp4  0  0  192.0.2.1.443  203.0.113.9.51001  "
           "SYN_RCVD\n"
           "tcp4  0  0  192.0.2.1.9999  203.0.113.9.51002  "
           "ESTABLISHED\n")
    snap = nw._live_from_text(out, "Darwin")
    assert 22 in snap["203.0.113.9"]
    assert snap["203.0.113.9"][443]["syn_recv"] == 1
    assert 9999 not in snap["203.0.113.9"]  # not a watched service


def _with_files(tmp, samples, probes):
    nw.SAMPLES = os.path.join(tmp, "samples.jsonl")
    nw.PROBES = os.path.join(tmp, "probes.jsonl")
    with open(nw.SAMPLES, "w") as f:
        for r in samples:
            f.write(json.dumps(r) + "\n")
    with open(nw.PROBES, "w") as f:
        for r in probes:
            f.write(json.dumps(r) + "\n")


def test_probe_events_scan_shape(tmp_path):
    samples = [{"ts": _ts(60), "snap": {
        "198.51.100.7": {22: {"established": 1},
                         1234: {"syn_recv": 3},
                         8930: {"established": 1},
                         8940: {"syn_recv": 2},
                         9119: {"established": 1}},
        "198.51.100.8": {22: {"established": 1}}}}]
    _with_files(str(tmp_path), samples, [])
    ev = nw._probe_events(24)
    assert ev["198.51.100.7"]["flagged"]
    assert "scan" in ev["198.51.100.7"]["kinds"]
    assert not ev["198.51.100.8"]["flagged"]


def test_probe_events_canary(tmp_path):
    probes = [{"ts": _ts(30), "ip": "192.0.2.44", "port": 2222}]
    _with_files(str(tmp_path), [], probes)
    ev = nw._probe_events(24)
    assert ev["192.0.2.44"]["flagged"]
    assert ev["192.0.2.44"]["kinds"] == ["canary"]
    assert ev["192.0.2.44"]["canary_hits"] == 1


def test_probe_events_old_window_ignored(tmp_path):
    probes = [{"ts": _ts(90000), "ip": "192.0.2.45", "port": 2222}]
    _with_files(str(tmp_path), [], probes)
    ev = nw._probe_events(24)
    assert "192.0.2.45" not in ev


def test_canary_ports_not_service_ports():
    # canaries must stay out of the socket-table sensor: a canary
    # connection is recorded in the probes file, not via netstat
    for p in nw.CANARY_PORTS:
        assert p not in nw.SERVICE_PORTS


def test_local_service_ports_merge(tmp_path):
    # owner-specific ports come from the untracked local config, not
    # from shipped source: they join the built-ins for the sensor.
    cfg = tmp_path / "netwatch.local.yaml"
    cfg.write_text("blocked: []\nservice_ports:\n  8930: test service\n")
    old, nw.CFG_PATH = nw.CFG_PATH, str(cfg)
    try:
        ports = nw.service_ports()
        assert ports[8930] == "test service"
        assert ports[22] == "SSH"  # built-ins still there
        out = ("tcp4  0  0  192.0.2.1.8930  203.0.113.9.51000  "
               "ESTABLISHED\n")
        snap = nw._live_from_text(out, "Darwin")
        assert 8930 in snap["203.0.113.9"]
    finally:
        nw.CFG_PATH = old


def test_save_blocked_preserves_other_keys(tmp_path):
    # blocking an IP must not wipe the rest of the local file
    cfg = tmp_path / "netwatch.local.yaml"
    cfg.write_text("blocked: []\nservice_ports:\n  8930: test service\n")
    old, nw.CFG_PATH = nw.CFG_PATH, str(cfg)
    try:
        nw._save_blocked(["203.0.113.9"])
        text = cfg.read_text()
        assert "203.0.113.9" in text
        assert "service_ports" in text and "8930" in text
    finally:
        nw.CFG_PATH = old


def main():
    import pathlib
    with tempfile.TemporaryDirectory() as tmp:
        test_live_snapshot_sees_service_ports()
        for fn in (test_probe_events_scan_shape,
                   test_probe_events_canary,
                   test_probe_events_old_window_ignored,
                   test_local_service_ports_merge,
                   test_save_blocked_preserves_other_keys):
            with tempfile.TemporaryDirectory(dir=tmp) as sub:
                fn(pathlib.Path(sub))
        test_canary_ports_not_service_ports()
    print("test_netwatch: ALL PASS")


if __name__ == "__main__":
    main()
