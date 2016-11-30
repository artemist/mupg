from . import Packet

class SymEncryptedIntegrityProtectedPacket(Packet):
    def __init__(self, data, packet_type):
        super().__init__(data, packet_type)
        self.version = data[0]
        if self.version != 1:
            raise ValueError("Does not support Symmetrically Encrypted Integrity Protected Packet version {}".format(self.version))
        self.enc_data = data[1:]
    
    def __str__(self):
        return "SymEncryptedIntegrityProtectedPacket(len={})".format(len(self.enc_data))
