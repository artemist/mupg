from . import SignatureSubpacket


class ByteListSubpacket(SignatureSubpacket):
    def __init__(self, data: bytes):
        super().__init__(data)
        self.algorithms = list(data[1:])

    def _to_name(self, algorithm):
        return str(algorithm)

    def __str__(self):
        return self.__class__.__name__ + "(" + \
               ", ".join([self._to_name(alg) for alg in self.algorithms]) + ")"


class PreferedHashSubpacket(ByteListSubpacket):
    def __init__(self, data: bytes):
        super().__init__(data)

    def _to_name(self, algorithm):
        d = {
            1: "MD5",
            2: "SHA1",
            3: "RIPEMD160",
            8: "SHA256",
            9: "SHA384",
            10: "SHA512",
            11: "SHA224"
        }
        return d.get(algorithm, str(algorithm))


class PreferedCompressionSubpacket(ByteListSubpacket):
    def __init__(self, data: bytes):
        super().__init__(data)

    def _to_name(self, algorithm):
        d = {
            0: "Uncompressed",
            1: "ZIP",
            2: "ZLIB",
            3: "BZIP2"
        }
        return d.get(algorithm, str(algorithm))


class PreferedSymmetricSubpacket(ByteListSubpacket):
    def __init__(self, data: bytes):
        super().__init__(data)

    def _to_name(self, algorithm):
        d = {
            0: "Plaintext",
            1: "IDEA",
            2: "3DES",
            4: "Blowfish",
            7: "AES128",
            8: "AES192",
            9: "AES256",
            10: "Twofish"
        }
        return d.get(algorithm, str(algorithm))


class FeaturesSubpacket(ByteListSubpacket):
    def __init__(self, data: bytes):
        super().__init__(data)

    def _to_name(self, algorithm):
        return "Modification Detection" if algorithm == 1 else str(algorithm)
