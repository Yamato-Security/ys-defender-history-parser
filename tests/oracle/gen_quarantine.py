"""Writes tests/fixtures/written/Quarantine/: a Defender quarantine folder as Defender writes
them (each part RC4-encrypted with Defender's key; an entry and a resource record a 60-byte
header, with the sections' sizes and their CRC-32s stored without the final inversion, then the
two sections, each encrypted on its own; a content named by its SHA-1), holding:

- an entry for a file (with its BackupRead streams: a security descriptor, its data, a
  Zone.Identifier stream), and its resource record;
- an entry for a service (its content a registry hive's first bytes) and a startup item;
- a content no entry holds.

The threat names, paths and identifiers are made up, and the file's data is a line of text:
nothing here is malware. Run: python3 -I gen_quarantine.py <tests/fixtures/written>
"""

import hashlib
import pathlib
import struct
import sys
import zlib

KEY = bytes.fromhex(
    "1E87781B8DBAA844CE69702C0C78B786A3F623B738F5EDF9AF83530FB3FC54FA"
    "A21EB9CF1331FD0F0DA954F687CB9E18279697900E53FB317C9CBCE48E23D053"
    "71ECC15951B8F3649D7CA33ED68DC9047E82C9BAAD9799D0D458CB847CA9FFBE"
    "3C8A775233557DDE13A8B14087CC1BC8F10F6ECDD083A959CFF84A9D1D50755E"
    "3E191818AF23E2293558766D2C07E25712B2CA0B535ED8F6C56CE73D24BDD029"
    "1771861A54B4C285A9A3DB7ACA6D224AEACD621DB9F2A22ED1E9E11D75BED7DC"
    "0ECB0A8E68A2FF1263408DC808DFFD164B116774CD0B9B8D05411ED6262E429B"
    "A495676B8398DB2F35D3C1B9CED52636F2765E1A95CB7CA4C3DDABDDBFF38253"
)


def rc4(data):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + KEY[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out = bytearray()
    i = j = 0
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)


def container(first, second):
    """A header and two sections, each encrypted on its own."""
    crc = lambda d: zlib.crc32(d) ^ 0xFFFFFFFF
    header = (bytes.fromhex("dbe8c501") + bytes.fromhex("01000100") + bytes(32)
              + struct.pack("<IIII", len(first), len(second), crc(first), crc(second))
              + bytes.fromhex("dbe8c502"))
    return rc4(header) + rc4(first) + rc4(second)


def guid_bytes(text):
    """A GUID's 16 bytes as Windows stores them."""
    a, b, c, d, e = text.split("-")
    return (struct.pack("<IHH", int(a, 16), int(b, 16), int(c, 16))
            + bytes.fromhex(d) + bytes.fromhex(e))


def filetime(text):
    """FILETIME of an ISO 8601 UTC time with 7 fractional digits."""
    import datetime
    whole, fraction = text.rstrip("Z").split(".")
    t = datetime.datetime.fromisoformat(whole).replace(tzinfo=datetime.timezone.utc)
    epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
    return int((t - epoch).total_seconds()) * 10_000_000 + int(fraction)


def field(ident, kind, data):
    return struct.pack("<HH", len(data), ident | (kind << 12)) + data


def resource(path, kind, fields):
    """A resource: its path, its fields' count, its type, then its fields, each at a multiple of
    4 bytes of the section (`base` the resource's offset in it)."""
    def build(base):
        out = path.encode("utf-16-le") + b"\0\0" + struct.pack("<H", len(fields))
        out += kind.encode() + b"\0"
        for f in fields:
            out += bytes((-(base + len(out))) % 4)
            out += f
        return out
    return build


def entry(guid, scan, time, threat_id, name, resources):
    first = (guid_bytes(guid) + guid_bytes(scan) + struct.pack("<QQI", filetime(time), threat_id, 1)
             + name.encode() + b"\0")
    count = len(resources)
    at = 4 + 4 * count
    offsets, body = [], b""
    for build in resources:
        at += (-at) % 4
        body += bytes((-(4 + 4 * count + len(body))) % 4)
        offsets.append(at)
        chunk = build(at)
        body += chunk
        at += len(chunk)
    second = struct.pack("<I", count) + struct.pack(f"<{count}I", *offsets) + body
    return container(first, second)


def stream(kind, attributes, name, data):
    name = name.encode("utf-16-le")
    return struct.pack("<IIQI", kind, attributes, len(data), len(name)) + name + data


def owner_descriptor():
    """A self-relative security descriptor whose owner is S-1-5-21-1111-2222-3333-1001."""
    sid = bytes([1, 5]) + (5).to_bytes(6, "big") + struct.pack("<5I", 21, 1111, 2222, 3333, 1001)
    return struct.pack("<BBHIIII", 1, 0, 0x8000, 20, 0, 0, 0) + sid


def write(root, relative, data):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def main():
    root = pathlib.Path(sys.argv[1]) / "Quarantine"
    data = b"A harmless line of text standing in for a quarantined tool.\r\n"
    content = (stream(3, 2, "", owner_descriptor()) + stream(1, 0, "", data)
               + stream(4, 0, ":Zone.Identifier:$DATA",
                        b"[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.com/tool.zip\r\n"))
    content_id = hashlib.sha1(content).hexdigest().upper()
    file_entry = "80012345-0000-0000-1A2B-3C4D5E6F7081"
    write(root, f"ResourceData/{content_id[:2]}/{content_id}", rc4(content))
    write(root, f"Resources/{content_id[:2]}/{content_id}",
          container(struct.pack("<Q", len(content)) + bytes.fromhex(content_id) + struct.pack("<I", 1),
                    guid_bytes(file_entry)))
    path = r"C:\Users\alice\Downloads\tool\tool.exe"
    write(root, f"Entries/{{{file_entry}}}", entry(
        file_entry, "6B1E0C2D-3F4A-4B5C-8D9E-0F1A2B3C4D5E", "2023-12-19T09:36:40.1234567Z",
        2147700000, "HackTool:Win32/Example!MSR",
        [resource("\\\\?\\" + path, "file", [
            field(0x02, 4, bytes.fromhex(content_id)),
            field(0x12, 6, struct.pack("<Q", len(data))),
            field(0x11, 6, struct.pack("<Q", filetime("2023-12-19T09:30:00.0000000Z"))),
            field(0x10, 6, struct.pack("<Q", filetime("2023-12-19T09:36:30.5000000Z"))),
            field(0x0F, 6, struct.pack("<Q", filetime("2023-12-19T09:29:59.0000000Z"))),
            field(0x0A, 3, struct.pack("<I", 0x20)),
            field(0x0C, 2, (path + "\0").encode("utf-16-le")),
            field(0x0D, 5, bytes.fromhex("0102030405060708")),
        ])]))

    hive = b"regf" + bytes(4092)
    hive_id = hashlib.sha1(hive).hexdigest().upper()
    service_entry = "80054321-0000-0000-9A8B-7C6D5E4F3021"
    write(root, f"ResourceData/{hive_id[:2]}/{hive_id}", rc4(hive))
    write(root, f"Entries/{{{service_entry}}}", entry(
        service_entry, "0A1B2C3D-4E5F-4A6B-9C7D-8E9F0A1B2C3D", "2023-12-19T09:40:00.0000000Z",
        2147711111, "Trojan:Win32/Example.A",
        [resource(r"HKLM\SYSTEM\CurrentControlSet\Services\ExampleSvc", "service", [
            field(0x0A, 4, bytes.fromhex(hive_id)),
            field(0x15, 3, struct.pack("<I", 16)),
            field(0x18, 2, "C:\\Windows\\example.exe\0".encode("utf-16-le")),
        ]),
         resource(r"C:\Windows\example.exe", "startup", [])]))

    # a content no entry holds
    orphan = stream(1, 0, "", b"left behind\r\n")
    orphan_id = hashlib.sha1(orphan).hexdigest().upper()
    write(root, f"ResourceData/{orphan_id[:2]}/{orphan_id}", rc4(orphan))


main()
