from . import Packet, _parse_be, _asymmetric_alg_name


class SignaturePacket(Packet):
    def __init__(self, data, type):
        super().__init__(data, type)
        self.version = self.data[0]

        if self.version == 3:
            assert(self.data[1] == 5)
            self.signature_type = self.data[2]
            self.creation = _parse_be(self.data[3:7])
            self.signer = _parse_be(self.data[7:15])
            self.pk_algorithm = self.data[15]
            self.hash_algorithm = self.data[16]
            self.hash_left = _parse_be(self.data[17:19])
            print("Skipping actual hash and signature verification")
            # TODO: Actually parse the signature part

        elif self.version == 4:
            self.signature_type = self.data[1]
            self.pk_algorithm = self.data[2]
            self.hash_algorithm = self.data[3]

            from .signature_subpacket.parser import parse_subpackets
            hashed_sub_length = _parse_be(self.data[4:6])
            self.hashed_subpackets = parse_subpackets(data[6:6+hashed_sub_length])

            unhashed_sub_length = _parse_be(self.data[6+hashed_sub_length:8+hashed_sub_length])
            self.unhashed_subpackets = parse_subpackets(data[8+hashed_sub_length:8+hashed_sub_length+unhashed_sub_length])
            rest = 8 + unhashed_sub_length + hashed_sub_length
            self.hash_left = _parse_be(self.data[rest:rest+2])
            # TODO: Actually parse the signature part
        else:
            raise ValueError("Invalid version for signature packet: {:d}".format(self.version))

    def __str__(self):
        s = "SignaturePacket(version={:d}, type={:d}, hash={:s}, hash_left={:s}, pk={:s}"\
            .format(self.version, self.signature_type, "TODO", hex(self.hash_left), _asymmetric_alg_name(self.pk_algorithm))
        if self.version == 3:
            s += ", signer={:d}".format(self.signer)
        elif self.version == 4:
            s += ", hashed_subpackets=[{:s}], unhashed_subpackets=[{:s}]"\
                .format(", ".join([str(p) for p in self.hashed_subpackets]),
                        ", ".join([str(p) for p in self.unhashed_subpackets]))

        return s + ")"
