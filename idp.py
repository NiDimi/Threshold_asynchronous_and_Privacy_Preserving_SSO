import petlib


def keyGen(params):
    """
    Generates the private and public key

    @:return the public key
    """
    (G, g, hs, o) = params
    priv = o.random()
    pub = priv * g
    return priv, pub


from petlib.ec import EcGroup
from petlib.bn import Bn
import random

from petlib.ec import EcGroup
from petlib.bn import Bn
import random


class PSPubKey:
    def __init__(self, g, gg, attribute_num):
        self.g = g
        self.gg = gg
        self.attribute_num = attribute_num
        self.XX = None
        self.Yi = []
        self.YYi = []


class PSSigner:
    def __init__(self, pk):
        self.pk = pk
        self.m_sk_X = None
        self.attribute_num = pk.attribute_num

    def key_gen(self):
        # Generate private key
        # m_x
        _sk_x = Bn().from_binary(random.getrandbits(256).to_bytes(32, 'big'))
        # m_X
        self.m_sk_X = self.pk.g.pt_mul(_sk_x)

        # Generate public key
        # public key: XX
        self.pk.XX = self.pk.gg.pt_mul(_sk_x)

        # public key: Y and YY for each attribute
        for i in range(self.attribute_num):
            y_item = Bn().from_binary(random.getrandbits(256).to_bytes(32, 'big'))
            Y_item = self.pk.g.pt_mul(y_item)
            self.pk.Yi.append(Y_item)
            YY_item = self.pk.gg.pt_mul(y_item)
            self.pk.YYi.append(YY_item)

        return self.pk


def setup():
    G = EcGroup(nid=713)
    g = G.hash_to_point(b"g")
    gg = G.hash_to_point(b"gg")  # Use a second hash for gg
    o = G.order()
    return G, g, gg, o


# Example usage
G, g, gg, o = setup()
attribute_num = 5
public_key = PSPubKey(g, gg, attribute_num)
signer = PSSigner(public_key)
generated_key = signer.key_gen()
