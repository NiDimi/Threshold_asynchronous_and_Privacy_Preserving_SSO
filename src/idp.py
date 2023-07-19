from hashlib import sha256

from bplib.bp import G1Elem
from petlib.bn import Bn

import helper
from pubKey import PubKey
from helper import BpGroupHelper
from request import Request


class IdP:
    # def __init__(self, id, sk, vk):
    #     self.__id = id
    #     self.__sk = sk
    #     self.__vk = vk

    def provide_id(self, sk, request):
        if not self.__verify_zkp(request):
            return 0
        return self.__sign_cred(request, sk)

    def __verify_zkp(self, request: Request):
        """
        Verify the zkp created by the user
        Va = a_i^c * g1^rk_i
        Vb = b_i^c * pk^rk_i * h ^ ra_i
        Vc = C^c * g1^rr * h_i ^ ra_i

        :param request: The request of the user containing the necessary elements
        :return: True if c = Hash(g1 || g2 || C || h || Vc || hs || Va || Vb) false otherwise
        """
        G, g1, hs, g2 = BpGroupHelper.G, BpGroupHelper.g1, BpGroupHelper.hs, BpGroupHelper.g2
        h = G.hashG1(request.C.export())
        (a, b) = zip(*request.cypher)
        c, rk, ra, rr = request.zkp
        # Compute the commitments
        Va = [c * a[i] + rk[i] * g1 for i in range(len(rk))]  # For the elgamal encryption the alpha
        # For the elgamal encryption the beta
        Vb = [c * b[i] + rk[i] * request.users_pk + ra[i] * h for i in range(len(request.cypher))]
        Vc = c * request.C + rr * g1  # For the commitment of the attributes (C)
        for i in range(len(ra)):
            Vc += ra[i] * hs[i]
        return c == helper.to_challenge([g1, g2, request.C, h, Vc] + hs + Va + Vb)

    def __sign_cred(self, request: Request, sk):
        """
        Basic PS signatures
        First we need to commit the public attributes since the user only commited the private C_pub = h^attributeP_i
        c_1 = a_j^y_i, c_2 = h^x * b_j ^ y_j

        :param request: The request of the user containing the necessary elements
        :param sk: The secret key of which to use to sign
        :return: the signature
        """
        G = BpGroupHelper.G
        h = G.hashG1(request.C.export())  # generate the common base with the user to add the public attributes
        (x, y) = sk
        (a, b) = zip(*request.cypher)
        C_pub = []  # Commit the public values
        for i, attribute in enumerate(request.attributes):
            if attribute != "":
                C_pub.append(Bn.from_binary(sha256(attribute).digest()) * h)
        c_1 = G1Elem.inf(G)
        for yi, ai in zip(y, a):
            c_1 += yi * ai
        c_2 = x * h
        for yi, bi in zip(y, list(b) + C_pub):  # We add all the private and then the public attributes
            c_2 += yi * bi

        return h, (c_1, c_2)
