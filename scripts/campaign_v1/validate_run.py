#!/usr/bin/env python3
"""ARCHIVIRT campaign_v1 — per-run validator (Article 2).

Emits one result object matching campaign_v1/schema/result.json.

Design guarantees:
  * A line counts as a Suricata EVE event ONLY if it parses as a JSON object
    carrying both "timestamp" and "event_type". Ansible headers, command
    output, empty files and framing markers are therefore rejected.
  * event_collected is true ONLY when >=1 valid EVE event exists.
  * alert_count counts event_type=="alert" records only.
  * detection_status is true ONLY when an alert matching the scenario
    (attacker -> target, inside the attack window) exists.
  * A run with no valid EVE alert does NOT become VALID for an attack scenario
    (SCN-001..004). SCN-005 is the false-positive baseline: zero alerts is the
    expected outcome, so it stays VALID with detection_status=false.
  * Latency is first_alert_timestamp - attack_start_timestamp, both from real
    recorded timestamps. If either is missing/unreliable -> null.

Stdlib only (no python-dateutil): avoids the root-context import failure that
previously zeroed Table 2.

Usage:
  validate_run.py EXPERIMENT_ID RUN_ID ENGINE MODE SCENARIO \
                  ATTACK_TIMES_FILE ATTACK_LOG_FILE EVE_FILE [STATS_FILE]
"""

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ATTACKER_IP = "10.0.4.10"
TARGET_IPS = {"10.0.2.11", "10.0.2.12", "10.0.2.13"}

# Ground truth per scenario: "attack" scenarios carry a real attack, the
# benign scenario is the negative control.
GROUND_TRUTH = {
    "SCN-001": "attack",
    "SCN-002": "attack",
    "SCN-003": "attack",
    "SCN-004": "attack",
    "SCN-005": "benign",
}

# Experimental scenario -> expected ARCHIVIRT signature id (ground-truth link
# between a scenario and the signature that must fire). IDS set = 20000xx,
# inline IPS set = 21000xx. Detection/blocking is scored ONLY against these.
SCENARIO_SID = {
    "SCN-001": {"ids": 2000001, "ips": 2100001},
    "SCN-002": {"ids": 2000002, "ips": 2100002},
    "SCN-003": {"ids": 2000003, "ips": 2100003},
    "SCN-004": {"ids": 2000004, "ips": 2100004},
}
ALL_ATTACK_SIDS = {s for m in SCENARIO_SID.values() for s in m.values()}

EXPECTED_DETECTION = {s: (gt == "attack") for s, gt in GROUND_TRUTH.items()}

# Window padding around the attack interval (milliseconds).
PRE_PAD_MS = 2000
POST_PAD_MS = 10000

ISO_RE = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})")


def parse_iso_ms(value):
    """Parse an ISO-8601 timestamp to epoch milliseconds, or None.

    Handles trailing 'Z', +HHMM / +HH:MM offsets, and sub-second precision
    finer than microseconds (Suricata and `date +%N` both emit nanoseconds).
    """
    if not value:
        return None
    s = value.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    # Normalise +HHMM -> +HH:MM
    m = re.search(r"([+-]\d{2})(\d{2})$", s)
    if m:
        s = s[: m.start()] + m.group(1) + ":" + m.group(2)
    # Trim fractional seconds to 6 digits (datetime max resolution).
    m = re.search(r"\.(\d+)", s)
    if m and len(m.group(1)) > 6:
        s = s[: m.start(1)] + m.group(1)[:6] + s[m.start(1) + len(m.group(1)) :]
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


def load_eve_events(eve_text):
    """Return only valid Suricata EVE events (dicts with timestamp+event_type)."""
    events = []
    for line in eve_text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not isinstance(obj, dict):
            continue
        if "timestamp" not in obj or "event_type" not in obj:
            continue
        events.append(obj)
    return events


def scenario_match(event, start_ms, end_ms):
    """True if an alert/drop event belongs to the scenario's attack flow."""
    src = event.get("src_ip")
    dst = event.get("dest_ip")
    direction_ok = (src == ATTACKER_IP and dst in TARGET_IPS) or (
        dst == ATTACKER_IP and src in TARGET_IPS
    )
    if not direction_ok:
        return False
    if start_ms is None or end_ms is None:
        # No reliable window: direction alone decides.
        return True
    ts = parse_iso_ms(event.get("timestamp"))
    if ts is None:
        return False
    return (start_ms - PRE_PAD_MS) <= ts <= (end_ms + POST_PAD_MS)


def is_block(event):
    if event.get("event_type") == "drop":
        return True
    action = str(event.get("alert", {}).get("action", "")).lower()
    return action in ("blocked", "drop", "dropped")


def main():
    args = sys.argv[1:]
    if len(args) < 8:
        sys.stderr.write(__doc__)
        sys.exit(2)

    experiment_id, run_id, engine, mode, scenario = args[0:5]
    times_file, attack_file, eve_file = args[5:8]
    stats_file = args[8] if len(args) > 8 else None

    times_text = Path(times_file).read_text(errors="replace") if Path(times_file).exists() else ""
    attack_text = Path(attack_file).read_text(errors="replace") if Path(attack_file).exists() else ""
    eve_text = Path(eve_file).read_text(errors="replace") if Path(eve_file).exists() else ""
    stats_text = (
        Path(stats_file).read_text(errors="replace")
        if stats_file and Path(stats_file).exists()
        else ""
    )

    limitations = []

    # --- Attack lifecycle -------------------------------------------------
    timestamps = ISO_RE.findall(times_text)
    attack_start_ts = timestamps[0] if len(timestamps) >= 1 else None
    attack_end_ts = timestamps[1] if len(timestamps) >= 2 else None
    attack_started = attack_start_ts is not None
    attack_completed = attack_end_ts is not None

    prereq_missing = "ARCHIVIRT_PREREQUISITE_MISSING" in attack_text or "PREREQUISITE_MISSING" in attack_text

    start_ms = parse_iso_ms(attack_start_ts)
    end_ms = parse_iso_ms(attack_end_ts)

    # --- EVE evidence -----------------------------------------------------
    events = load_eve_events(eve_text)
    event_collected = len(events) >= 1
    alerts = [e for e in events if e.get("event_type") == "alert"]
    alert_count = len(alerts)

    # traffic_observed: inferred from EVE only (enabled types: alert/http/dns/tls).
    # Packet-level counters are not exported, so absence of EVE events cannot
    # prove absence of traffic -> null with a recorded limitation.
    if event_collected:
        traffic_observed = True
    else:
        traffic_observed = None
        limitations.append(
            "traffic_observed=null: no EVE event; packet-level counters not exported "
            "(stats EVE type not enabled)"
        )

    # --- Detection (scored against the scenario's expected SID only) ------
    # Mode-aware: in inline IPS mode the firing signature is the drop SID
    # (21000xx), in IDS mode the alert SID (20000xx).
    ground_truth = GROUND_TRUTH.get(scenario)
    expected_sid = SCENARIO_SID.get(scenario, {}).get("ips" if mode == "ips" else "ids")

    def sid_of(ev):
        return ev.get("alert", {}).get("signature_id")

    # Alerts in the attack flow (attacker<->target) within the window.
    flow_alerts = [a for a in alerts if scenario_match(a, start_ms, end_ms)]
    # Which ARCHIVIRT attack signatures fired at all (any scenario's SID).
    fired_attack_sids = sorted({sid_of(a) for a in flow_alerts if sid_of(a) in ALL_ATTACK_SIDS})

    # Alerts matching THIS scenario's expected signature.
    matching_alerts = [a for a in flow_alerts if sid_of(a) == expected_sid]
    matching_alerts_sorted = sorted(
        matching_alerts, key=lambda e: parse_iso_ms(e.get("timestamp")) or 0
    )

    if ground_truth == "benign":
        # Negative control: positive == any tested attack signature fired.
        detection_status = len(fired_attack_sids) >= 1
        classification = "FP" if detection_status else "TN"
        first_alert_timestamp = None
    elif ground_truth == "attack":
        detection_status = len(matching_alerts_sorted) >= 1
        classification = "TP" if detection_status else "FN"
        first_alert_timestamp = (
            matching_alerts_sorted[0].get("timestamp") if matching_alerts_sorted else None
        )
    else:
        detection_status = len(matching_alerts_sorted) >= 1
        classification = "NOT_APPLICABLE"
        first_alert_timestamp = (
            matching_alerts_sorted[0].get("timestamp") if matching_alerts_sorted else None
        )

    # --- Blocking (IPS only; scored against the scenario's drop SID) ------
    expected_ips_sid = SCENARIO_SID.get(scenario, {}).get("ips")
    if mode == "ips":
        blocks = [
            e for e in events
            if is_block(e) and scenario_match(e, start_ms, end_ms)
            and (sid_of(e) in (expected_sid, expected_ips_sid) or sid_of(e) is None)
        ]
        blocks_sorted = sorted(blocks, key=lambda e: parse_iso_ms(e.get("timestamp")) or 0)
        blocking_status = len(blocks_sorted) >= 1
        first_block_timestamp = blocks_sorted[0].get("timestamp") if blocks_sorted else None
    else:
        blocking_status = None
        first_block_timestamp = None

    # --- Latency (from real timestamps only) ------------------------------
    detection_latency_ms = None
    if first_alert_timestamp is not None and start_ms is not None:
        alert_ms = parse_iso_ms(first_alert_timestamp)
        if alert_ms is not None and alert_ms >= start_ms:
            detection_latency_ms = alert_ms - start_ms
        else:
            limitations.append(
                "detection_latency_ms=null: first alert precedes attack start "
                "(clock skew between attacker and monitor)"
            )
    elif detection_status:
        limitations.append("detection_latency_ms=null: missing attack_start or alert timestamp")

    blocking_latency_ms = None
    if mode == "ips" and first_block_timestamp is not None and start_ms is not None:
        block_ms = parse_iso_ms(first_block_timestamp)
        if block_ms is not None and block_ms >= start_ms:
            blocking_latency_ms = block_ms - start_ms

    # --- Run status -------------------------------------------------------
    expect_detection = EXPECTED_DETECTION.get(scenario, True)

    if prereq_missing:
        run_status = "PREREQUISITE_MISSING"
        invalid_reason = "attacker prerequisite missing; scenario not executed"
    elif not attack_started:
        run_status = "INVALID"
        invalid_reason = "attack did not start (no start timestamp)"
    elif not attack_completed:
        run_status = "INVALID"
        invalid_reason = "attack did not complete (no end timestamp)"
    elif not event_collected:
        run_status = "INVALID"
        invalid_reason = "no valid Suricata EVE event collected"
    elif expect_detection and not detection_status:
        run_status = "INVALID"
        invalid_reason = "attack scenario produced no matching EVE alert"
    else:
        run_status = "VALID"
        invalid_reason = ""

    if limitations:
        suffix = " | limitations: " + "; ".join(limitations)
        invalid_reason = (invalid_reason + suffix) if invalid_reason else suffix.strip(" |")

    result = {
        "experiment_id": experiment_id,
        "run_id": run_id,
        "engine": engine,
        "mode": mode,
        "scenario": scenario,
        "attack_started": attack_started,
        "attack_completed": attack_completed,
        "traffic_observed": traffic_observed,
        "event_collected": event_collected,
        "detection_status": detection_status,
        "blocking_status": blocking_status,
        "ground_truth": ground_truth,
        "expected_sid": expected_sid,
        "fired_attack_sids": fired_attack_sids,
        "classification": classification,
        "alert_count": alert_count,
        "attack_start_timestamp": attack_start_ts,
        "attack_end_timestamp": attack_end_ts,
        "first_alert_timestamp": first_alert_timestamp,
        "first_block_timestamp": first_block_timestamp,
        "detection_latency_ms": detection_latency_ms,
        "blocking_latency_ms": blocking_latency_ms,
        "run_status": run_status,
        "invalid_reason": invalid_reason,
    }

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
