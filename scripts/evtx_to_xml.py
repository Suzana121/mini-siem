"""Read binary Windows .evtx files as one-line Event XML.

`iter_event_xml(path)` yields one `<Event ...>...</Event>` string per record,
newlines collapsed, which is exactly what `app/parsers/windows_event.py`
parses. Needs the optional `python-evtx` package (see requirements-dev.txt);
a missing install raises EvtxUnavailable with the fix.

Usage: python -m scripts.evtx_to_xml Security.evtx > security.xml
"""

import re
import sys
from collections.abc import Iterator

_BETWEEN_TAGS = re.compile(r">\s+<")
_WHITESPACE_RUN = re.compile(r"\s*[\r\n]+\s*")


class EvtxUnavailable(RuntimeError):
    """python-evtx is not installed."""


def is_evtx(path: str) -> bool:
    return str(path).lower().endswith(".evtx")


def collapse_xml(xml: str) -> str:
    """Put one pretty-printed record on a single line, keeping text content intact."""
    xml = _BETWEEN_TAGS.sub("><", xml.strip())
    return _WHITESPACE_RUN.sub(" ", xml)


def iter_event_xml(path: str) -> Iterator[str]:
    try:
        from Evtx.Evtx import Evtx
    except ImportError as e:
        raise EvtxUnavailable(
            "reading .evtx files needs the python-evtx package: pip install -r requirements-dev.txt"
        ) from e

    with Evtx(str(path)) as log:
        for record in log.records():
            try:
                xml = record.xml()
            except Exception as e:  # a corrupt record must not abort the whole file
                print(f"evtx: skipping unreadable record: {e}", file=sys.stderr)
                continue
            yield collapse_xml(xml)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    try:
        for line in iter_event_xml(sys.argv[1]):
            print(line)
    except EvtxUnavailable as e:
        raise SystemExit(str(e))
