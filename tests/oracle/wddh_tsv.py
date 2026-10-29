"""What Orange Cyberdefense's wddh (its `wddh` command) reads from every detection history file in
tests/fixtures/, as the TSV tests/wddh.rs compares: one line per value, the file (relative to
tests/fixtures), a key and the value, the keys named as this crate names them (positions for the
values whose meaning isn't known, as in wddh's doc.md).

wddh's known differences are evened out here, not in the comparison: its strings keep their
terminating NUL, a FILETIME of 0 is 1601-01-01 (left out here), a zero GUID is a GUID (left out),
and a status it has no name for is left out. Times are microseconds since 1970; wddh's go through a
float, within 2 microseconds of the FILETIME: tests/wddh.rs allows for that.

Run: python3 -I wddh_tsv.py <tests/fixtures> > wddh.tsv
"""

import datetime
import gzip
import json
import pathlib
import subprocess
import sys
import tempfile

STATUS = {
    "Unknown": 0, "Detected": 1, "Cleaned": 2, "Quarantined": 3, "Removed": 4, "Allowed": 5,
    "Blocked": 6, "QuarantineFailed": 102, "RemoveFailed": 103, "AllowFailed": 104,
    "Abondoned": 105, "BlockedFailed": 107,
}


def text(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        if value.startswith("<L:4|T:0|V:b'"):
            # A type 0 value wddh doesn't read: its four bytes.
            import ast
            return str(int.from_bytes(ast.literal_eval(value[11:-1]), "little"))
        return value.rstrip("\0")
    return str(value)


def time(value):
    """Microseconds since 1970 (UTC)."""
    if value is None or value.startswith("1601-01-01T00:00:00"):
        return None
    moment = datetime.datetime.fromisoformat(value)
    since = moment - datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
    return (since.days * 86_400 + since.seconds) * 1_000_000 + since.microseconds


def lines(name, out):
    rows = []

    def put(key, value):
        if value is not None:
            rows.append(f"{name}\t{key}\t{text(value)}")

    header = out["header"]
    put("threat_id", header["threat_id"])
    put("id", header["detection_id"].upper())
    put("version", header["magic_version"])
    put("threat_name", header["threat_name"])
    flags = out["flag_section"]
    put("2.0", flags["flag_1"])
    put("severity_id", flags["flag_2"])
    put("category_id", flags["flag_3"])
    put("2.3", flags["flag_4"])
    put("2.4", flags["flag_5"])
    put("threat_status_id", STATUS.get(flags["threat_status_id"].split(".")[1]))
    put("list", ",".join(str(n) for n in flags["flag_list"]))
    resources = out["alert_details"] + out["alert_details_2"]
    put("resources", len(resources))
    for i, resource in enumerate(resources):
        put(f"resource.{i}.kind", resource["ressource_type"])
        put(f"resource.{i}.location", resource["ressource_location"])
        put(f"resource.{i}.flags", resource["flag_1"])
        blob = resource.get("blob")
        for key, value in (blob if isinstance(blob, dict) else {}).items():
            put(f"resource.{i}.{key}", value)
    metadata = out["metadata"]
    put("status_changed", time(metadata["last_threat_status_change"]))
    put("status_error_code", metadata["threat_status_error_code"])
    put("4.2", metadata["flag_1"])
    quarantine = metadata["unknown_uid"].upper()
    put("quarantine_id", None if set(quarantine) <= set("0-") else quarantine)
    put("execution_status_id", metadata["current_threat_execution_id"])
    details = out["metadata_2"]
    put("6.0", details["flag_1"])
    put("user", details["domain_user"])
    put("source_type_id", details["flag_2"])
    put("process", details["process_name"])
    put("initial_detection", time(details["initial_detection_time"]))
    put("remediation", time(details["remediation"]))
    for key, position in [("flag_3", "6.4"), ("flag_4", "6.5"), ("flag_5", "6.6"),
                          ("flag_6", "6.8"), ("flag_7", "6.10"), ("unknown_1", "6.11"),
                          ("flag_8", "6.12"), ("domain_user_group", "6.13"),
                          ("flag_9", "6.14")]:
        put(position, details[key])
    footer = out["footer"]
    for key, position in [("unknown_1", "8.0"), ("flag_1", "8.1"), ("flag_2", "8.2"),
                          ("flag_3", "8.3"), ("flag_4", "8.4")]:
        put(position, footer[key])
    return rows


def main():
    root = pathlib.Path(sys.argv[1])
    rows = []
    with tempfile.TemporaryDirectory() as scratch:
        for path in sorted(root.rglob("*")):
            guid = path.name.removesuffix(".gz")
            if not path.is_file() or len(guid) != 36 or guid.count("-") != 4:
                continue
            source = path
            if path.suffix == ".gz":
                source = pathlib.Path(scratch) / guid
                source.write_bytes(gzip.decompress(path.read_bytes()))
            out = pathlib.Path(scratch) / "out.json"
            subprocess.run(["wddh", "-i", str(source), "-o", str(out)], check=True,
                           capture_output=True)
            rows += lines(path.relative_to(root).as_posix(), json.loads(out.read_text()))
    for row in sorted(rows):
        print(row)


main()
