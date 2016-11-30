def encrypt(data: bytes, n: int, e: int) -> bytes:
    m = 0
    for b in data:
        m = (m << 8) | b
    c = pow(m, e, n)
    out = bytearray()
    while c > 0:
        out.insert(0, c & 0xFF)
        c >>= 8
    return bytes(out)

def decrypt(data: bytes, n: int, d: int) -> bytes:
    return encrypt(data, n, d)