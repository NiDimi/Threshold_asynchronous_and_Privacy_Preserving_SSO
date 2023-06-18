from hashlib import sha256

from bplib.bp import BpGroup
from petlib.bn import Bn


class BpGroupHelper:
    """
    Just a helper function to instantiate the BpGroup() once and then be able to call it from all functions
    """

    G = g1 = g2 = e = o = None

    @staticmethod
    def setup():
        BpGroupHelper.G = BpGroup()
        BpGroupHelper.g1, BpGroupHelper.g2 = BpGroupHelper.G.g1, BpGroupHelper.G.g2
        BpGroupHelper.e, BpGroupHelper.o = BpGroupHelper.G.pair, BpGroupHelper.G.order()


def to_challenge(elements):
    """
    Packages a challenge in a bijective way
    Taken from https://github.com/gdanezis/petlib/blob/master/examples/zkp.py
    and modified a bit

    :param elements: The elements to hash and concatinate
    """
    elem = [len(elements)] + elements
    elem_str = map(str, elem)
    elem_len = map(lambda x: "%s||%s" % (len(x), x), elem_str)
    state = "|".join(elem_len)
    H = sha256()
    H.update(state.encode("utf8"))
    return Bn.from_binary(H.digest())
