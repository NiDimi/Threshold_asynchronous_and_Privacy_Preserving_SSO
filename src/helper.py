from hashlib import sha256

from bplib.bp import BpGroup, G2Elem
from petlib.bn import Bn
from petlib.pack import encode, decode
from binascii import hexlify, unhexlify


class BpGroupHelper:
    """
    Just a helper function to instantiate the BpGroup() once and then be able to call it from all functions
    """

    G = g1 = g2 = e = o = hs = g_secret = h_secret = None

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
        # q+1 to add for the additional y we need for the openers. One h for each attribute + 1 h for the secret
        BpGroupHelper.hs = [BpGroupHelper.G.hashG1(("h%s" % i).encode()) for i in range(q + 1)]
        # Generators for the commitments in the key generation of the IdPs
        BpGroupHelper.g_secret = BpGroupHelper.G.hashG1("s_secret".encode())
        BpGroupHelper.h_secret = BpGroupHelper.G.hashG1("h_secret".encode())


class ElGamal:
    """
    Helper class to handle the ElGamal encryption's
    """

    def __init__(self, g):
        self.__keygen(g)

    def __keygen(self, g):
        """"
        Generates the secret and public keys
        """
        self.sk = BpGroupHelper.o.random()
        self.pk = self.sk * g

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
        We will use Horner's method to evaluate the polynomials https://en.wikipedia.org/wiki/Horner%27s_method
        p(x) = coff_0 + x*(coff_1 + x*(coff_2 + ... + x*(coff_n-1 + x*coff_n)))
        where coff_0 is the secret

        :param coeff: Coefficients of the polynomial
        :param x: The value x at which we evaluate the polynomial
        :return: The result of the evaluation
        """
        result = coeff[-1]  # Take coff_n and start multiplying with x and adding the next coeff one. Following formula
        for coff_i in reversed(coeff[:-1]):
            result = result * x + coff_i
        return result

    @staticmethod
    def lagrange_interpolation(indexes):
        """
        Helper that generates all the Langrange interpolations
        l(x) = (xj-x)/(xj-xi) where i and j are the indexes and i different from j
        In our case the x is zero because we want to evaluate the polynomial at 0 in order to return the secret

        :param indexes: The list of indices to interpolate
        :return: The list of Langrange coefficients
        """
        if len(indexes) == 1:
            return [1]
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


"""
The following two functions are used to pack and unpack data in order to communicate over AWS
"""


def pack(x):
    return hexlify(encode(x)).decode('utf-8')


def unpack(x):
    return decode(unhexlify(x.encode('utf-8')))
