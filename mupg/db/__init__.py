import json

def db_read(file: str) -> dict:
    try:
        return json.load(open(file))
    except FileNotFoundError:
        return dict()

def db_write(file: str, data: dict):
    f = open(file, "w")
    json.dump(data, f)
    f.close()
