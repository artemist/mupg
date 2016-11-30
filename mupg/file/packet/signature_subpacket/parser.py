from typing import Tuple, List
from . import SignatureSubpacket
from .time_subpacket import CreationTimeSubpacket, ExpirationTimeSubpacket
from .prefered_algorithm_subpacket import PreferedCompressionSubpacket, PreferedHashSubpacket,\
    PreferedSymmetricSubpacket, FeaturesSubpacket
from .flags_subpacket import KeyFlagsSubpacket
from .. import _parse_new_length

subpacket_types = {
    2: CreationTimeSubpacket,
    9: ExpirationTimeSubpacket,
    11: PreferedSymmetricSubpacket,
    21: PreferedHashSubpacket,
    22: PreferedCompressionSubpacket,
    27: KeyFlagsSubpacket,
    30: FeaturesSubpacket
}


def parse_subpacket(orig_data: bytes) -> Tuple[SignatureSubpacket, int]:
    # We have a new style packet
    data_start, data_len = _parse_new_length(orig_data, offset=0)

    packet_type_raw = orig_data[data_start]
    packet_type = packet_type_raw & 0b01111111

    if packet_type_raw & 0b10000000 and packet_type not in subpacket_types:
        print(*[bin(x)[2:].rjust(8, '0') for x in orig_data])
        # If we have the critical bit and do not recognise it, we must fail
        raise RuntimeError("This program does not support critical subpacket type {:d}".format(packet_type))

    packet = subpacket_types.get(packet_type, SignatureSubpacket)\
        (orig_data[data_start:data_start + data_len])

    return packet, data_len + data_start


def parse_subpackets(orig_data: bytes) -> List[SignatureSubpacket]:
    packets = []
    offset = 0
    while offset < len(orig_data):
        new_packet, len_diff = parse_subpacket(orig_data[offset:])
        offset += len_diff
        packets.append(new_packet)
    return packets
