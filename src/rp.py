from hashlib import sha256

from bplib.bp import G2Elem
from petlib.bn import Bn

from pubKey import PubKey
from credproof import CredProof
import helper
from helper import BpGroupHelper


class RP:

    def verify_id(self, proof: CredProof, aggr_vk, public_m):
        G, g2, e = BpGroupHelper.G, BpGroupHelper.g2, BpGroupHelper.e
        (g2, _, beta) = aggr_vk

        if not self.__verify_zkp(proof, aggr_vk):
            return False
        aggr = G2Elem.inf(G)
        # for i, attribute in enumerate(proof.attributes):
        #     if attribute != "":
        #         aggr += Bn.from_binary(sha256(attribute).digest()) * beta[i]
        for i, m in enumerate(public_m):
            aggr += m * beta[2]
        h, s = proof.sig
        return not h.isinf() and e(h, proof.k + aggr) == e(s + proof.nu, g2)

    def __verify_zkp(self, proof: CredProof, aggr_vk):
        # g1, hs, _ = BpGroupHelper.g1, BpGroupHelper.hs, BpGroupHelper.g2
        # (g2, alpha, beta) = aggr_vk
        # (h, _) = proof.sig
        # (c, rm, rt) = proof.zkp
        # Aw = c * proof.k + rt * g2 + (1 - c) * alpha
        # j = 0
        # for i, attribute in enumerate(proof.attributes):
        #     if attribute == "":
        #         Aw += rm[j] * beta[i]
        #         j += 1
        # Bw = c * proof.nu + rt * h
        # return c == helper.to_challenge([g1, g2, alpha, Aw, Bw] + hs + beta)
        return True
