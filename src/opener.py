from bplib.bp import G2Elem, GTElem

from helper import ElGamal, BpGroupHelper, Polynomial
from credproof import CredProof

ledger = {}
ban_users = {}


class Opener:

    def __init__(self):
        self.__elgamal = ElGamal(BpGroupHelper.g2)
        self.pk = self.__elgamal.pk

    def calculate_s(self, c, s1):
        e = BpGroupHelper.e
        c0, c1 = c
        return e(s1, c1 - c0 * self.__elgamal.sk)

    def reconstruct_key_share(self, c):
        c0, c1 = c
        return c1 - c0 * self.__elgamal.sk


def check_sig(S, proof: CredProof, vk):
    G, e = BpGroupHelper.G, BpGroupHelper.e
    filter = []
    indexes = []
    for i, s in enumerate(S):
        if s is not None:
            filter.append(s)
            indexes.append(i + 1)
    l = Polynomial.lagrange_interpolation(indexes)
    secret = S[0] ** l[0]
    for i in range(1, len(S)):
        secret *= S[i] ** l[i]
    h, s = proof.sig
    g2, a, b = vk
    return e(h, proof.attributes_commitment) * e(proof.key_commitment, b[-1]) == e(s + proof.vu, g2)


def deanonymize(openers, proof: CredProof, vk):
    for i in ledger:
        c = ledger[i]
        S = [openers[i].calculate_s(c[ci], proof.sig[0]) for i, ci in enumerate(c)]
        sec = check_sig(S, proof, vk)
        if sec:
            secret_shares = [openers[i].reconstruct_key_share(c[ci]) for i, ci in enumerate(c)]
            rev_sig = create_revoked_sig(secret_shares)
            ban_users[i] = rev_sig
            return i
    return 0


def create_revoked_sig(sk_shares):
    G = BpGroupHelper.G
    filter = []
    indexes = []
    for i, s in enumerate(sk_shares):
        if s is not None:
            filter.append(s)
            indexes.append(i + 1)
    l = Polynomial.lagrange_interpolation(indexes)
    sk = sk_shares[0] * l[0]
    for i in range(1, len(sk_shares)):
        sk += sk_shares[i] * l[i]
    return sk
