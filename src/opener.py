from bplib.bp import G2Elem, GTElem

from helper import ElGamal, BpGroupHelper, Polynomial
from credproof import CredProof

ledger = {}
ban_users = {}


class Opener:

    def __init__(self):
        # Generate the el gamal keys and set the pk as a public attribute
        self.__elgamal = ElGamal(BpGroupHelper.g2)
        self.pk = self.__elgamal.pk

    def calculate_t(self, c, h):
        """
        Calculate the openers share from the c the user created given the h from the signature

        :param c: The c that the user published for the opening
        :param h: The first part of the sig
        :return: e(h, c1 * c0 ^ (-osk))
        """
        e = BpGroupHelper.e
        c0, c1, _ = c
        return e(h, c1 - c0 * self.__elgamal.sk)

    def reconstruct_key_share(self, c):
        """
        Reconstruct the secret of the user in order to generate the revoked_sig. This function is run by each opner
        on his share

        :param c: The c that the user published for the opening
        :return: c1 *  c0 ^ (-osk)
        """
        c0, c1, _ = c
        return c1 - c0 * self.__elgamal.sk


def check_sig(T, proof: CredProof, vk):
    """
    Check if the sig provided by the RP is a valid sig of a user in order to verify that they should deanonymize him
    e(h, attributes_commitment) * secret == e(s + vu, g2). Basically reconstructing a shamir secret share

    :param T: All the t's from the openers as a list
    :param proof: The proof of the user
    :param vk: The aggregated vk of the IdPs that created the sig
    :return: True if the sig is correct false otherwise
    """
    G, e = BpGroupHelper.G, BpGroupHelper.e
    filter = []
    indexes = []
    for i, s in enumerate(T):
        if s is not None:
            filter.append(s)
            indexes.append(i + 1)
    l = Polynomial.lagrange_interpolation(indexes)
    secret = T[0] ** l[0]
    for i in range(1, len(T)):
        secret *= T[i] ** l[i]
    h, s = proof.sig
    g2, _, beta = vk
    return e(h, proof.attributes_commitment) * secret == e(s + proof.vu, g2)


def deanonymize(openers, proof: CredProof, vk):
    """
    Called normally from the RP to deannonymize a malicious user

    :param openers: All the openers necessary
    :param proof: The proof the user tried to send to the RP
    :param vk: The aggregated vk of the IdPs that created the sig
    :return: 0 if the user was not found the id otherwise
    """
    for i in ledger:
        c = ledger[i]
        T = [openers[i].calculate_t(c[ci], proof.sig[0]) for i, ci in enumerate(c)]
        sec = check_sig(T, proof, vk)
        if sec:
            secret_shares = [openers[i].reconstruct_key_share(c[ci]) for i, ci in enumerate(c)]
            rev_sig = create_revoked_sig(secret_shares)
            # Add the user into the ban list
            ban_users[i] = rev_sig
            return i
    return 0


def create_revoked_sig(secret_shares):
    """
    Take all the shares of the secret and reconstruct the secret in order to generate the revoked_sig
     Basically reconstructing a shamir secret share.

    :param secret_shares: All the shares of the openers
    :return: The revoked sig
    """
    filter = []
    indexes = []
    for i, s in enumerate(secret_shares):
        if s is not None:
            filter.append(s)
            indexes.append(i + 1)
    l = Polynomial.lagrange_interpolation(indexes)
    revoked_sig = secret_shares[0] * l[0]
    for i in range(1, len(secret_shares)):
        revoked_sig += secret_shares[i] * l[i]
    return revoked_sig
