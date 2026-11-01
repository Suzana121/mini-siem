"""Download the free DB-IP City Lite database (MaxMind .mmdb format) into data/.

    python scripts/download_geoip.py

DB-IP Lite is licensed CC BY 4.0 (attribution: https://db-ip.com) and needs
no account. MaxMind GeoLite2-City also works: point GEOIP_DB at its .mmdb.
"""

import gzip
import shutil
import urllib.request
from datetime import date, timedelta
from pathlib import Path

TARGET = Path(__file__).resolve().parent.parent / "data" / "dbip-city-lite.mmdb"


def main() -> None:
    TARGET.parent.mkdir(exist_ok=True)
    this_month = date.today().replace(day=1)
    last_month = (this_month - timedelta(days=1)).replace(day=1)
    # The current month's file appears a few days into the month.
    for month in (this_month, last_month):
        url = f"https://download.db-ip.com/free/dbip-city-lite-{month:%Y-%m}.mmdb.gz"
        try:
            with urllib.request.urlopen(url, timeout=60) as response, open(TARGET, "wb") as out:
                shutil.copyfileobj(gzip.GzipFile(fileobj=response), out)
        except Exception as exc:
            print(f"{url}: {exc}")
            continue
        print(f"saved {TARGET} ({TARGET.stat().st_size // 1_000_000} MB) from {url}")
        return
    raise SystemExit("download failed")


if __name__ == "__main__":
    main()
