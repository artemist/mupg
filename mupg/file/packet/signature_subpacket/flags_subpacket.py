from . import SignatureSubpacket


class KeyFlagsSubpacket(SignatureSubpacket):
    def __init__(self, data):
        super().__init__(data)
        self.flags = data[-1]

    flag_names = ["Certify",
                  "Sign",
                  "Encrypt",
                  "Encrypt Storage",
                  "Private Split",
                  "Authenticate",
                  "Private Multiple"]

    def __str__(self):
        return "KeyFlagsSubpacket(" + \
               ", ".join([self.flag_names[i] for i in range(len(self.flag_names)) if self.flags & (1 << i)]) + ")"
