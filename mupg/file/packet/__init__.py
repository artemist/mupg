from typing import Tuple, List

class Packet:
    def __init__(self, data: bytes, type: int):
        self.length = len(data)
        self.data = data
        self.type = type

    def __str__(self):
        return "Packet(type={}, len={})".format(self.type, self.length)


def _parse_be(data: bytes) -> int:
    n = 0
    for i in range(0, len(data)):
        n = n << 8 | data[i]
    return n


def _parse_mpi(data: bytes) -> int:
    return _parse_mpi_len(data)[0]


def _parse_mpi_len(data: bytes) -> Tuple[int, int]:
    length = data[1] << 8 | data[0]
    return _parse_be(data[2:2+length]), length + 2


def _parse_mpis(data: bytes, num_mpis: int) -> List[int]:
    l = []
    offset = 0
    for i in range(num_mpis):
        mpi, mpi_len = _parse_mpi_len(data[offset:])
        offset += mpi_len
        l.append(mpi)
    return l


def _asymmetric_alg_name(alg_id: int) -> str:
    if alg_id in range(1, 4):
        return "RSA"
    elif alg_id == 17:
        return "DSA"
    elif alg_id == 16:
        return "Elgamal"
    elif alg_id == 22:
        return "Ed25519"
    else:
        return "Unknown"


def _parse_new_length(orig_data: bytes, offset=1) -> Tuple[int, int]:
    if orig_data[offset] < 192:
        return 1+offset, orig_data[offset]
    elif orig_data[offset] < 224:
        return 2+offset, ((orig_data[offset] - 192) << 8) + orig_data[offset+1] + 192
    elif orig_data[offset] < 255:
        # We have an partial body length, which must be parsed at a higher level
        return 1+offset, -1
    elif orig_data[0] == 255:
        return 5+offset, (orig_data[offset+1] << 24) + (orig_data[offset+2] << 16) + (orig_data[offset+3] << 8) + orig_data[offset+4]


def _parse_old_length(orig_data: bytes) -> Tuple[int, int]:
    if orig_data[0] & 0b11 == 0b11:
        # If it has indeterminate length, we will assume it goes to the end of the file
        return 1, len(orig_data) - 1

    len_len = 1 << (orig_data[0] & 0b11)    # This gets us 1, 2, and 4 easily
    # Parse big endian
    cur_len = 0
    for i in range(1, len_len + 1):
        cur_len = (cur_len << 8) | orig_data[i]

    return len_len + 1, cur_len

def _parse_partial_len(data: bytes) -> Tuple[bytes, int]:
    offset, length = _parse_new_length(data, offset=0)
    if length == -1:
        length = 1 << (data[0] & 0x1F)
        sub_data, sub_len = _parse_partial_len(data[length+offset:])
        return data[offset:offset+length] + sub_data, sub_len + length + offset
    else:
        # Otherwise, we have recursed into a normal packet
        return data[offset:offset+length], offset + length
