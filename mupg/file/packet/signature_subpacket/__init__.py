class SignatureSubpacket():
    def __init__(self, data: bytes):
        self.data = data
        self.type = self.data[0] & 0b111111
        self.critical = True if self.data[0] & 0b1000000 else False

    def __str__(self):
        return "SignatureSubpacket(type={:d}, len={:d})".format(self.type, len(self.data))
