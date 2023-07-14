from hashlib import sha256

from bplib.bp import G1Elem
from petlib.bn import Bn

import helper
from helper import BpGroupHelper, ElGamal, Polynomial
from pubKey import PubKey
from request import Request
from typing import List, Tuple
from credproof import CredProof


class Client:
    def __init__(self):
        """
        Constructor for the client

        :param idp_pk: The public key of the IdP
        :param secret: This secret will be used to build an identity to the RP such as IdP cant use the attributes and
        the client cant create multiple users in the RP
        """
        self.elgamal = ElGamal()
        # self.__idp_pk: PubKey = idp_pk
        # # Used for blinding and unblinding the signatures
        # self.__t = None
        # self.__secret = Bn.from_binary(sha256(secret).digest())

    def request_id(self, private_m, public_m):
        G, o, g1, hs = BpGroupHelper.G, BpGroupHelper.o, BpGroupHelper.g1, BpGroupHelper.hs
        attributes = private_m + public_m
        assert len(attributes) <= len(hs)
        C, r = self.__create_commitment(attributes)
        h = G.hashG1(C.export())
        # El-gamal encryption
        enc = []
        # for i, attribute in enumerate(attributes):
        #     if attribute[1]:
        #         enc.append(self.elgamal.encrypt(Bn.from_binary(sha256(attribute[0]).digest()), h))
        for m in private_m:
            enc.append(self.elgamal.encrypt(m, h))

        (a, b, k) = zip(*enc)
        c = list(zip(a, b))
        # ZKP
        # pi_s = self.__create_zkp_idp(self.elgamal.gamma, cypher, C, k, r, attributes)
        pi_s = 0
        # public_attributes = ["" if attr[1] else attr[0] for attr in attributes]
        return Request(self.elgamal.gamma, C, c, pi_s, [])

    def __create_commitment(self, attributes):
        G, o, g1, hs = BpGroupHelper.G, BpGroupHelper.o, BpGroupHelper.g1, BpGroupHelper.hs
        r = o.random()
        C = r * g1
        for i, attribute in enumerate(attributes):
            C += attribute * hs[i]
        return C, r

    def __create_zkp_idp(self, pk, cypher, C, k, r, attributes):
        G, o, g1, hs, g2 = BpGroupHelper.G, BpGroupHelper.o, BpGroupHelper.g1, BpGroupHelper.hs, BpGroupHelper.g2
        # Compute witnesses
        wr = o.random()
        wk = [o.random() for _ in k]
        wm = [o.random() for _ in attributes]
        # Compute h
        h = G.hashG1(C.export())
        # Compute the commitments
        Aw = [g1 * wki for wki in wk]  # for k's
        Bw = []
        Cw = wr * g1
        for i, attribute in enumerate(attributes):
            if attribute[1]:
                Bw.append(wk[i] * pk + wm[i] * h)
            Cw += wm[i] * hs[i]

        c = helper.to_challenge([g1, g2, C, h, Cw] + hs + Aw + Bw)
        rr = (wr - c * r) % o
        rk = [(wk[i] - c * k[i]) % o for i in range(len(wk))]
        rm = [(wm[i] - c * Bn.from_binary(sha256(attributes[i][0]).digest())) % o for i in range(len(wm))]
        return c, rk, rm, rr

    def unbind_sig(self, sig_prime):
        h, c_prime = sig_prime
        sig = h, self.elgamal.decrypt(c_prime)
        return sig

    def agg_cred(self, sigs):
        G = BpGroupHelper.G
        filter = []
        indexes = []
        for i, sig in enumerate(sigs):
            if sig is not None:
                filter.append(sig)
                indexes.append(i + 1)
        l = Polynomial.lagrange_interpolation(indexes)
        h, s = zip(*filter)
        aggr_sig = G1Elem.inf(G)
        for i in range(len(filter)):
            aggr_sig += l[i] * s[i]
        return h[0], aggr_sig

    def verify_sig(self, sig, aggr_vk, public_m, private_m):
        e = BpGroupHelper.e
        g2, alpha, beta = aggr_vk
        h, s = sig
        attributes = private_m + public_m
        verification_result = alpha
        for i, attribute in enumerate(attributes):
            verification_result += beta[i] * attribute
        return not h.isinf() and e(h, verification_result) == e(s, g2)


    def prove_id(self, sig, attributes, aggr_vk):
        o = BpGroupHelper.o
        g2, alpha, beta = aggr_vk
        r = o.random()
        h_prime, s_prime = self.__randomize_signature(sig)
        sig_prime = h_prime, s_prime
        k = r * g2 + alpha

        for i, attribute in enumerate(attributes):
            if attribute[1]:
                k += Bn.from_binary(sha256(attribute[0]).digest()) * beta[i]
        nu = r * h_prime
        # zkp
        pi_v = self.__create_zkp_rp(attributes, aggr_vk, sig_prime, r)
        public_attributes = ["" if attr[1] else attr[0] for attr in attributes]
        return CredProof(k, nu, sig_prime, pi_v, public_attributes)

    def __randomize_signature(self, sig):
        o = BpGroupHelper.o
        r = o.random()
        h, s = sig
        return h * r, s * r

    def __create_zkp_rp(self, attributes, aggr_vk, sig, t):
        G, o, g1, hs, _ = BpGroupHelper.G, BpGroupHelper.o, BpGroupHelper.g1, BpGroupHelper.hs, BpGroupHelper.g2
        (g2, alpha, beta) = aggr_vk
        (h, _) = sig
        wt = o.random()
        Bw = wt * h
        wm = []
        Aw = wt * g2 + alpha
        for i, attribute in enumerate(attributes):
            if attribute[1]:
                wm.append(o.random())
                Aw += wm[i] * beta[i]
        c = helper.to_challenge([g1, g2, alpha, Aw, Bw] + hs + beta)
        j = 0
        rm = []
        for i, attribute in enumerate(attributes):
            if attribute[1]:
                rm.append((wm[j] - c * Bn.from_binary(sha256(attribute[0]).digest())) % o)
                j += 1
        rt = (wt - c * t) % o
        return c, rm, rt
