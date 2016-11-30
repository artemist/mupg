import bz2
import zlib

from . import Packet


class CompressedDataPacket(Packet):
    def __init__(self, data, packet_type):
        super().__init__(data, packet_type)
        self.algorithm = data[0]
        if self.algorithm == 0:
            self.method = "Uncompressed"
            self.raw_data = data[1:]

        elif self.algorithm == 1:
            self.method = "zip"
            self.raw_data = zlib.decompress(data[1:], -zlib.MAX_WBITS)

        elif self.algorithm == 2:
            self.method = "zlib"
            self.raw_data = zlib.decompress(data[1:])

        elif self.algorithm == 3:
            self.method = "bz2"
            self.raw_data = bz2.decompress(data[1:])

        from mupg.file.packet_reader import parse_packets
        self.packets = parse_packets(self.raw_data)

    def __str__(self):
        return ("CompressedDataPacket(len={}, uncompressed_len={}, " +
                "algorithm={}, subpackets=[{}])") \
            .format(self.length, len(self.raw_data), self.method,
                    ", ".join([str(packet) for packet in self.packets]))
