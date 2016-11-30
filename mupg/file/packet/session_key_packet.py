from mupg.file.packet import Packet, _asymmetric_alg_name


class SessionKeyPacket(Packet):
    def __init__(self, data, type):
        super().__init__(data, type)
        self.version = data[0]
        if self.version != 3:
            raise ValueError("Unsupported version")

        self.keyid = data[1:9]
        self.algorithm = data[9]
        self.encrypted_data = data[10:]

    def __hex__(self):
        return "0x" + "".join([hex(b)[2:] for b in self.keyid])

    def __str__(self):
        return "AsymmetricEncryptedSessionKeyPacket(ktype={}, recipient={}, data_len={})"\
            .format(_asymmetric_alg_name(self.algorithm), self.__hex__(), len(self.encrypted_data))