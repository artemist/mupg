from typing import Tuple

from mupg.file.packet.compressed_data_packet import CompressedDataPacket
from mupg.file.packet.public_key_packet import PublicKeyPacket
from mupg.file.packet.session_key_packet import SessionKeyPacket
from mupg.file.packet.signature_packet import SignaturePacket
from mupg.file.packet.encrypted_integrity_protected_packet import SymEncryptedIntegrityProtectedPacket
from mupg.file.packet.user_id_packet import UserIDPacket
from mupg.file.packet import _parse_new_length, _parse_old_length, _parse_partial_len, Packet

packet_types = {
    1: SessionKeyPacket,
    2: SignaturePacket,
    6: PublicKeyPacket,
    8: CompressedDataPacket,
    13: UserIDPacket,
    14: PublicKeyPacket,
    18: SymEncryptedIntegrityProtectedPacket
}


def parse_packet(orig_data: bytes) -> Tuple[Packet, int]:
    tag = orig_data[0]
    if tag & 128 == 0:
        raise ValueError("Not an OpenPGP Packet")

    if tag & 64 == 0:
        # We have an old style packet
        packet_type = (tag >> 2) & 0b1111
        data_start, data_len = _parse_old_length(orig_data)

    else:
        # We have a new style packet
        data_start, data_len = _parse_new_length(orig_data)

        packet_type = tag & 0b11111

        if data_len == -1:
            # We have a partial body len
            new_data, skip_len = _parse_partial_len(orig_data[1:])
            return packet_types.get(packet_type, Packet)(new_data, packet_type), skip_len + 1



    packet = packet_types.get(packet_type, Packet) \
        (orig_data[data_start:data_start + data_len], packet_type)

    return packet, data_len + data_start


def parse_packets(orig_data: bytes):
    offset = 0
    while offset < len(orig_data):
        new_packet, len_diff = parse_packet(orig_data[offset:])
        offset += len_diff
        yield new_packet
