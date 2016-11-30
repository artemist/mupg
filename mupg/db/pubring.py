from typing import List

from mupg.file.packet.public_key_packet import PublicKeyPacket
from base64 import b64encode, b64decode

def list_pubkeys(db: dict) -> List:
    return [PublicKeyPacket(b64decode(data), -1) for data in db.get("pubring", [])]

def insert_key(db: dict, key: PublicKeyPacket) -> dict:
    kdata = b64encode(key.data).decode("UTF-8")
    if "pubring" in db:
        db["pubring"].append(kdata)
    else:
        db["pubring"] = [kdata]
    return db