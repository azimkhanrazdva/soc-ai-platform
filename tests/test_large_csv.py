import csv
import io

from soc_ai.splunk import _set_max_csv_field_size


def test_csv_parser_accepts_large_fields():
    previous = csv.field_size_limit()
    try:
        _set_max_csv_field_size()
        rows = list(csv.DictReader(io.StringIO("event\n" + ("x" * 200_000) + "\n")))
    finally:
        csv.field_size_limit(previous)
    assert len(rows[0]["event"]) == 200_000
