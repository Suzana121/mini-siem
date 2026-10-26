"""Run the detection rules over a log file offline and print the alerts.

Usage (from the repo root): python -m scripts.detect samples/auth.log [--source auth.log] [--rules rules]
"""

import argparse
from pathlib import Path

from app.detection import DEFAULT_RULES_DIR, DetectionEngine, load_rules
from app.parsers import PARSERS


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("path")
    parser.add_argument("--source", default="auth.log")
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES_DIR)
    args = parser.parse_args()

    parse = PARSERS[args.source]
    engine = DetectionEngine(load_rules(args.rules))
    alerts = []
    with open(args.path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if event := parse(line):
                alerts.extend(engine.process(event))

    for alert in alerts:
        techniques = ", ".join(t.id for t in alert.mitre)
        print(f"{alert.timestamp:%Y-%m-%d %H:%M:%S}  {alert.severity.upper():8}  {alert.rule_id:28} [{techniques}]  {alert.group}")
    print(f"\n{len(alerts)} alert(s), {len(engine.rules)} rules loaded")


if __name__ == "__main__":
    main()
