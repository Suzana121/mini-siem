"""Run the full pipeline (enrich, detect, score, dedup) over a log file offline.

Usage (from the repo root):
    python -m scripts.detect samples/auth.log [--source auth.log] [--rules rules] [--intel samples/intel]
"""

import argparse
import asyncio
from pathlib import Path

from app.detection import DEFAULT_RULES_DIR, DetectionEngine, load_rules
from app.enrichment import Enricher, GeoIP, ThreatIntel
from app.parsers import PARSERS
from app.pipeline import Pipeline
from app.store import MemoryAlertStore

ROOT = DEFAULT_RULES_DIR.parent


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("path")
    parser.add_argument("--source", default="auth.log")
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES_DIR)
    parser.add_argument("--intel", type=Path, action="append", help="threat-intel feed directory (repeatable)")
    parser.add_argument("--geoip", type=Path, default=ROOT / "data" / "dbip-city-lite.mmdb")
    args = parser.parse_args()

    intel_dirs = args.intel or [ROOT / "intel"]
    enricher = Enricher(
        GeoIP(args.geoip) if args.geoip.exists() else None,
        ThreatIntel.from_directories([d for d in intel_dirs if d.is_dir()]),
    )
    store = MemoryAlertStore()
    pipeline = Pipeline(DetectionEngine(load_rules(args.rules)), store, enricher)

    parse = PARSERS[args.source]
    with open(args.path, encoding="utf-8", errors="replace") as f:
        await pipeline.handle([e for line in f if (e := parse(line))])

    alerts = sorted(await store.list(limit=10_000), key=lambda a: a.first_seen)
    for alert in alerts:
        techniques = ", ".join(t.id for t in alert.mitre)
        repeats = f" x{alert.occurrences}" if alert.occurrences > 1 else ""
        print(
            f"{alert.timestamp:%Y-%m-%d %H:%M:%S}  {alert.severity.upper():8} risk {alert.risk_score:3}  "
            f"{alert.rule_id:28} [{techniques}]{repeats}"
        )
        if alert.threat.listed:
            print(f"{'':42}threat intel: {', '.join(alert.threat.feeds)}")
    print(f"\n{len(alerts)} alert(s), {len(pipeline.engine.rules)} rules, intel feeds: {enricher.intel.sizes or 'none'}")


if __name__ == "__main__":
    asyncio.run(main())
