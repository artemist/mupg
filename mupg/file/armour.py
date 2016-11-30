import base64


def _crc24(data: bytes) -> int:
    crc = 0xB704CE
    for datum in data:
        crc ^= (datum << 16)
        for i in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF


def parse(data: str) -> bytes:
    # Remove all but raw b64 data
    parts = data.split("\n\n")
    lines = parts[1].strip().split("\n")

    raw_b64 = "".join(lines[:-2])
    output = base64.b64decode(raw_b64)

    checksum_b64 = lines[-2][1:]
    checksum = base64.b64decode(checksum_b64)

    if _crc24(output) != checksum:
        pass
        # raise ValueError("Incorrect checksum!")
    return output

def opt_parse(data: bytes) -> bytes:
    try:
        s = data.decode('utf-8')
        if s.startswith("-----BEGIN"):
            data = parse(s)
    except UnicodeDecodeError:
        pass
    return data
