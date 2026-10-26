#!/usr/bin/env python3
"""Builds site/iran-status.json from Cloudflare Radar (Iran network traffic). Needs env RADAR_TOKEN (Radar read-only token).

"Normal" = median of the SAME HOUR over the previous 14 days, so a quiet night is not an outage. The newest hour is
skipped because Radar fills it in later. Output is a tiny static file the V2RayRivals app downloads.
"""
import json, os, sys, time, urllib.request
from datetime import datetime, timezone

TOKEN = os.environ.get("RADAR_TOKEN", "").strip()
BASE = "https://api.cloudflare.com/client/v4/radar/netflows/timeseries"


def fetch(product):
    url = f"{BASE}?location=IR&dateRange=21d&aggInterval=1h&product={product}&normalization=MIN0_MAX&format=JSON"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {TOKEN}", "User-Agent": "iran-status/1.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.load(r)
    if not data.get("success", True) or "result" not in data:
        raise RuntimeError("Radar answered without a result: " + str(data.get("errors")))
    return data["result"]


def to_float(x):
    try:
        v = float(x)
        return None if v != v else v
    except (TypeError, ValueError):
        return None


def analyze(values):
    """values: hourly list (float | None), oldest first. Returns (ratio, chart24) or None."""
    last = max((i for i, v in enumerate(values) if v is not None), default=-1) - 1
    if last < 24 * 8:
        return None

    def baseline(i):
        same = sorted(v for k in range(1, 15) if i - 24 * k >= 0 for v in [values[i - 24 * k]] if v is not None and v > 0)
        return same[len(same) // 2] if len(same) >= 5 else None

    def ratio(i):
        b = baseline(i)
        x = values[i] if 0 <= i < len(values) else None
        return None if b is None or x is None else x / b

    recent = [q for q in (ratio(last - k) for k in range(3)) if q is not None]
    if not recent:
        return None
    chart, prev = [], 100.0
    for i in range(last - 23, last + 1):
        q = ratio(i)
        if q is not None:
            prev = q * 100
        chart.append(int(max(0.0, min(150.0, prev))))
    return sum(recent) / len(recent), chart


def disruption(result):
    """True if Radar flags an OUTAGE / TRAFFIC_ANOMALY that is still running or ended within the last 3 hours."""
    ann = (((result.get("meta") or {}).get("confidenceInfo") or {}).get("annotations")) or []
    now = time.time()
    for a in ann:
        if a.get("eventType") not in ("OUTAGE", "TRAFFIC_ANOMALY"):
            continue
        end = a.get("endDate")
        if not end:
            return True
        try:
            if datetime.fromisoformat(end.replace("Z", "+00:00")).timestamp() > now - 3 * 3600:
                return True
        except ValueError:
            return True
    return False


def level_of(worst):
    return "normal" if worst >= 0.90 else "minor" if worst >= 0.70 else "major" if worst >= 0.40 else "outage"


def series(product):
    result = fetch(product)
    vals = [to_float(v) for v in ((result.get("serie_0") or {}).get("values") or [])]
    a = analyze(vals)
    return None if a is None else (a[0], a[1], disruption(result))


def build(total, http):
    worst = min(x[0] for x in (total, http) if x is not None)
    if total[2] or (http is not None and http[2]):
        worst = min(worst, 0.60)
    part = lambda s: None if s is None else {"pct": int(s[0] * 100), "series": s[1]}
    return {"v": 1, "updated": int(time.time()), "level": level_of(worst), "total": part(total), "http": part(http)}


def main():
    if not TOKEN:
        sys.exit("RADAR_TOKEN is not set")
    total = series("ALL")
    if total is None:
        sys.exit("Radar returned too little data for Iran")
    try:
        http = series("HTTP")
    except Exception as e:  # the HTTP line is optional
        print("HTTP series skipped:", e)
        http = None
    out = build(total, http)
    os.makedirs("site", exist_ok=True)
    with open("site/iran-status.json", "w", encoding="utf-8") as f:
        json.dump(out, f, separators=(",", ":"))
    with open("site/index.html", "w", encoding="utf-8") as f:
        f.write("<!doctype html><meta charset=utf-8><title>Iran status feed</title><p>iran-status.json</p>")
    print(json.dumps(out))


if __name__ == "__main__":
    main()
