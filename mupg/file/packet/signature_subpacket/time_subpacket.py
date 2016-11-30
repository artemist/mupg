from . import SignatureSubpacket
from .. import _parse_be
from datetime import datetime


class CreationTimeSubpacket(SignatureSubpacket):
    def __init__(self, data: bytes):
        super().__init__(data)
        self.time = datetime.utcfromtimestamp(_parse_be(data[1:5]))

    def __str__(self):
        return "CreationTimeSubpacket(" + self.time.strftime('%Y-%m-%d %H:%M:%S') + ")"


class ExpirationTimeSubpacket(SignatureSubpacket):
    def __init__(self, data: bytes):
        super().__init__(data)
        self.time = _parse_be(data[1:5])

    def __str__(self):
        s = "ExpirationTimeSubpacket("
        if self.time == 0:
            s += "No Expiration"
        else:
            s += str(self.time)
        return s + ")"
