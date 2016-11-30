from . import Packet


class UserIDPacket(Packet):
    def __init__(self, data, type):
        super().__init__(data, type)
        self.user = data.decode("utf-8")

    def __str__(self):
        return "User ID packet for \"{:s}\"".format(self.user)
