from hashlib import sha256

from bplib.bp import G2Elem
from petlib.bn import Bn

from credproof import CredProof
import helper
from helper import BpGroupHelper


class RP:

    def verify_id(self, proof: CredProof, aggr_vk):
        """
        Chck e(h, k_priv * k_pub) = e(s * vu, g2)

        :param proof:
        :param aggr_vk:
        :return:
        """
        G, g2, e = BpGroupHelper.G, BpGroupHelper.g2, BpGroupHelper.e
        (g2, _, beta) = aggr_vk
        # Check the ZKP
        if not self.__verify_zkp(proof, aggr_vk):
            return False
        # Add the public attributes in the k
        aggr = G2Elem.inf(G)
        for i, attribute in enumerate(proof.attributes):
            if attribute != "":
                aggr += Bn.from_binary(sha256(attribute).digest()) * beta[i]

        h, s = proof.sig
        return not h.isinf() and e(h, proof.k + aggr) == e(s + proof.vu, g2)

    def __verify_zkp(self, proof: CredProof, aggr_vk):
        """
        Verify the zkp create by the user
        Vr = vu^c * h^rr
        Va = a^c * g2^rr * a^(1-c) * b_i^ra_i

        :param proof: The proof of the user containing the necessary elements
        :param aggr_vk: The aggregated vk from the IdP's
        :return: True if c = (g1 || g2 || alpha || Va || Vr || hs || beta) false otherwise
        """
        g1, hs = BpGroupHelper.g1, BpGroupHelper.hs
        (g2, alpha, beta) = aggr_vk
        (h, _) = proof.sig
        (c, ra, rr) = proof.zkp
        Va = c * proof.k + rr * g2 + (1 - c) * alpha  # For the attributes
        for i, attribute in enumerate(proof.attributes):
            if attribute == "":
                Va += ra[i] * beta[i]
        Vr = c * proof.vu + rr * h  # For the commitment r
        return c == helper.to_challenge([g1, g2, alpha, Va, Vr] + hs + beta)

