from . import Packet, _parse_be, _parse_mpis
from datetime import datetime
from hashlib import sha1


class PublicKeyPacket(Packet):
    def __init__(self, data, packet_type):
        super().__init__(data, packet_type)

        self.version = data[0]
        if self.version in [2, 3]:
            self.creation = datetime.utcfromtimestamp(_parse_be(data[1:5]))
            self.expire_time = _parse_be(data[5:7])
            self.algorithm = data[7]
            self.alg_name = "RSA"
            self.material = _parse_mpis(data[8:], 2)

        elif self.version == 4:
            self.creation = datetime.utcfromtimestamp(_parse_be(data[1:5]))
            self.algorithm = data[5]
            if self.algorithm in range(1, 4):
                self.alg_name = "RSA"
                self.material = _parse_mpis(data[6:], 2)
            elif self.algorithm == 17:
                self.alg_name = "DSA"
                self.material = _parse_mpis(data[6:], 4)
            elif self.algorithm == 16:
                self.alg_name = "Elgamal"
                self.material = _parse_mpis(data[6:], 2)
            elif self.algorithm == 22:
                self.alg_name = "Ed25519"
                self.material = _parse_mpis(data[6:], 1)
            else:
                raise ValueError("Unknown algorithm number {}".format(self.algorithm))
        else:
            raise ValueError("Unsupported Public Key Packet Version {}".format(self.version))

    def __str__(self):
        s =  "PublicKeyPacket(version={}, algorithm={}, creation={}"\
            .format(self.version, self.alg_name, self.creation.strftime('%Y-%m-%d %H:%M:%S'))
        if self.version == 4:
            s += ", fingerprint=\"{}\"".format(self.gpg_fingerprint)
        return s + ")"

    def _fingerprint_hash(self) -> sha1:
        # TODO: Support version 3 keys
        sha = sha1()
        l = len(self.data)
        blen = bytes([l >> 8, l & 0xFF])
        sha.update(b'\x99' + blen + self.data)
        return sha

    @property
    def hex_fingerprint(self) -> str:
        return self._fingerprint_hash().hexdigest()

    @property
    def gpg_fingerprint(self) -> str:
        s = self.hex_fingerprint.upper()
        parts = [s[i:i+4] for i in range(0, len(s), 4)]
        parts.insert(int(len(parts) / 2), "")   # We need to insert a split in the middle to match gpg
        return " ".join(parts)