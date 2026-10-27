"""Download the offline GeoIP/ASN tables used by src/analytics/enrichment.py into data/.

Source: https://iptoasn.com (public domain, PDDL; no account). About 7 MB for IPv4, 2 MB for IPv6, compressed.
Run it yourself, then re-run it now and then (the tables are refreshed hourly upstream; monthly is plenty).

    python -m scripts.fetch_enrichment_data
"""
import gzip
import os
import shutil
import sys
import tempfile
import urllib.request

from src.analytics.enrichment import DATA_DIR

FILES = {"ip2asn-v4.tsv": "https://iptoasn.com/data/ip2asn-v4.tsv.gz",
         "ip2asn-v6.tsv": "https://iptoasn.com/data/ip2asn-v6.tsv.gz"}


def fetch(name: str, url: str) -> int:
    os.makedirs(DATA_DIR, exist_ok=True)
    target = os.path.join(DATA_DIR, name)
    with tempfile.NamedTemporaryFile(dir=DATA_DIR, delete=False, suffix=".part") as tmp:
        try:
            with urllib.request.urlopen(url, timeout=60) as response, gzip.GzipFile(fileobj=response) as plain:
                shutil.copyfileobj(plain, tmp)
        except BaseException:
            tmp.close()
            os.unlink(tmp.name)
            raise
    os.replace(tmp.name, target)  # never leave a half-written table behind
    return os.path.getsize(target)


if __name__ == "__main__":
    for name, url in FILES.items():
        try:
            print(f"{name}: {fetch(name, url) / 1e6:.1f} MB from {url}")
        except OSError as e:
            sys.exit(f"{name}: download failed ({e}). Nothing was changed.")
