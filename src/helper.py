from hashlib import sha256

from bplib.bp import BpGroup, G1Elem, G2Elem
from petlib.bn import Bn


class BpGroupHelper:
    """
    Just a helper function to instantiate the BpGroup() once and then be able to call it from all functions
    """

    G = g1 = g2 = e = o = hs = None

    @staticmethod
    def setup(q):
        """
        Sets up the parameters of the class
        :param q: The maximum number of the attributes
        """
        assert q > 0
        BpGroupHelper.G = BpGroup()
        BpGroupHelper.g1, BpGroupHelper.g2 = BpGroupHelper.G.gen1(), BpGroupHelper.G.gen2()
        BpGroupHelper.e, BpGroupHelper.o = BpGroupHelper.G.pair, BpGroupHelper.G.order()
        BpGroupHelper.hs = [BpGroupHelper.G.hashG1(("h%s" % i).encode()) for i in range(q)]


class ElGamal:
    """
    Helper class to handle the ElGamal encryption's
    """

    def __init__(self):
        self.__keygen()

    def __keygen(self):
        """"
        Generates the secret and public keys
        """
        self.sk = BpGroupHelper.o.random()
        self.pk = self.sk * BpGroupHelper.g1

    def encrypt(self, m):
        """
        El gamal basic encryption
        :param m: The message to encrypt
        :return: The ciphertext
        """
        g1, o = BpGroupHelper.g1, BpGroupHelper.o
        r = o.random()
        return r * g1, r * self.pk + m, r

    def decrypt(self, c):
        """
        El gamal basic decryption
        :param c: The ciphertext
        :return: Unecrypted message
        """
        a, b = c
        return b - self.sk * a


class Polynomial:
    """
    Helper function that handles the polynomials for secret sharing
    """

    @staticmethod
    def evaluate(coeff, x):
        """
        So we take the coefficient, and we multiply with the value x raised in the degree i
        Based on how many coefficient we have can find the degree of the polynomial
        Basically the first coefficient will be coeff[0] * x^0 then coeff[1] * x^1 then coeff[2] * x^2 etc.
        """
        return sum([coeff[i] * (Bn(x) ** i) for i in range(len(coeff))])

    @staticmethod
    def lagrange_interpolation(indexes):
        """
        Helper that generates all the Langrange interpolations
        l(x) = (xj-x)/(xj-xi) where i and j are the indexes and i different from j
        In our case the x is zero because we want to evaluate the polynomial at 0 in order to return the secret

        :param indexes: The list of indices to interpolate
        :return: The list of Langrange coefficients
        """
        o = BpGroupHelper.o
        l = []
        for i in indexes:
            numerator, denominator = 1, 1
            for j in indexes:
                if j != i:
                    numerator = (numerator * j) % o
                    denominator = (denominator * (j - i)) % o
            l.append((numerator * denominator.mod_inverse(o)) % o)
        return l


def to_challenge(elements):
    """
    Packages a challenge in a bijective way
    Taken from https://github.com/gdanezis/petlib/blob/master/examples/zkp.py
    and modified a bit

    :param elements: The elements to hash and concatinate
    """
    elements = [element.export() for element in elements]
    elem = [len(elements)] + elements
    elem_str = map(str, elem)
    elem_len = map(lambda x: "%s||%s" % (len(x), x), elem_str)
    state = "|".join(elem_len)
    H = sha256()
    H.update(state.encode("utf8"))
    return Bn.from_binary(H.digest())


def ttp_keygen(t, n):
    """
    Generates the key for the threshold credentials. This function is supposingly run by a Trusted Third Party (TTP)

    :param t: the threshold required
    :param n: the number of total authorities
    :return: the secret keys for each authority (sk) and the verification keys for each authority (vk)
    """
    g2, o, hs = BpGroupHelper.g2, BpGroupHelper.o, BpGroupHelper.hs
    # We need to make sure that the threshold is smaller that the number of authorities
    assert n >= t > 0
    # Generate the polynomials (these are the coefficients, which are just random numbers)
    v = [o.random() for _ in
         range(0, t)]  # Basically we generate how many number we need. The degree will be t-1 so t num
    w = [[o.random() for _ in range(0, t)] for _ in range(len(BpGroupHelper.hs))]  # For every v we need q w's so t * q

    # Generates the secret shares using shamir secret sharing
    x = [Polynomial.evaluate(v, i) % o for i in range(1, n + 1)]
    y = [[Polynomial.evaluate(wj, i) % o for wj in w] for i in range(1, n + 1)]

    # Finally set the keys
    sk = list(zip(x, y))
    vk = [(g2, x[i] * g2, [y[i][j] * g2 for j in range(len(y[i]))]) for i in range(len(sk))]
    return sk, vk


def agg_key(vks):
    """
    Helper function to aggregate the verification keys from all the IdPs

    :param vks: A list of the verification keys from eacch IdP
    :return: The final vk that can be used to check the signature
    """
    G, g2 = BpGroupHelper.G, BpGroupHelper.g2
    # Since we using threshold we dont need all the keys so we check for None's and we keep only the ones with values
    # We also need their indexes for the langrange interpolation
    filtered_vks = [(i + 1, vk) for i, vk in enumerate(vks) if vk is not None]
    indexes, filter_vk = zip(*filtered_vks)
    l = Polynomial.lagrange_interpolation(indexes)

    _, alpha, beta = zip(*filter_vk)
    aggr_alpha = G2Elem.inf(G)
    aggr_beta = [G2Elem.inf(G) for _ in range(len(beta[0]))]
    for j in range(len(filter_vk)):
        aggr_alpha += l[j] * alpha[j]
        for i in range(len(beta[0])):
            aggr_beta[i] += l[j] * beta[j][i]
    return g2, aggr_alpha, aggr_beta


def hash_attributes(attributes):
    """
    Takes a tuple of the style (attribute, Private(true or false)) and hashes them

    :param attributes: Tuple with attributes
    :return: Hashed the value of the attribute to SHA256 and turn them into BN
    """
    hashed_attributes = []
    for attribute in attributes:
        hashed_attributes.append((Bn.from_binary(sha256(attribute[0]).digest()), attribute[1]))
    return hashed_attributes


def sort_attributes(attributes):
    """
    Sorts a list of tuples (attribute, boolean), placing private attributes first and public last.

    :param attributes: List of tuples, where each tuple contains a byte string and a boolean
    :return: Sorted list of tuples
    """
    return sorted(attributes, key=lambda x: not x[1])
