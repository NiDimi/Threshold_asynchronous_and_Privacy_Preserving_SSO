import sys

sys.path.append("../../src")
from idp import IdP


class IdPWrapper:
    """
    Just a wrapper on IdP's since we only care about creating them not doing the whole
    secret sharing protocol. So we dont modify the IdP and just create this class to pass the keys
    The parameters are just used for the key sharing protocol so any arbitrary number is fine.

    """

    idp = None

    def __init__(self):
        self.idp = IdP(1, 1, 2)

    def getIdP(self, sk, vk):
        self.idp.vk = vk
        self.idp.sk = sk
        return self.idp



