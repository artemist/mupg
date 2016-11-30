from sys import argv

from mupg.file.armour import opt_parse
from mupg.file.packet.public_key_packet import PublicKeyPacket
from mupg.file.packet_reader import parse_packets
from mupg.db import db_read, db_write
from mupg.db.pubring import insert_key, list_pubkeys


def dump_packets(file):
    data = open(file, "rb").read()

    for packet in parse_packets(opt_parse(data)):
        print(packet)

def import_key(file: str, db_file="/tmp/db.json"):
    packets = parse_packets(opt_parse(open(file, "rb").read()))
    db = db_read(db_file)
    for packet in packets:
        if type(packet) is PublicKeyPacket:
            insert_key(db, packet)
    db_write(db_file, db)

def list_keys(db_file="/tmp/db.json"):
    db = db_read(db_file)
    keys = list_pubkeys(db)
    for key in keys:
        print(key)

if argv[1] == "dump":
    dump_packets(argv[2])
elif argv[1] == "import_key":
    import_key(argv[2])
elif argv[1] == "list_keys":
    list_keys()
else:
    print("Usage: {} <command> <args>\nCurrently defined commands: dump, import_key, list_keys".format(argv[0]))
    exit(1)