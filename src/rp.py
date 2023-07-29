from hashlib import sha256

from bplib.bp import G2Elem
from petlib.bn import Bn

from credproof import CredProof
import helper
from helper import BpGroupHelper
from opener import ban_users


class RP:

    def __init__(self, domain):
        self.domain = domain  # The RPs domain

    def verify_id(self, proof: CredProof, aggr_vk):
        """
        Chck e(h, k_priv * k_pub) = e(s * vu, g2)

        :param proof:
        :param aggr_vk:
        :return:
        """
        # Check the ZKP
        if not self.__verify_zkp(proof, aggr_vk):
            return False
        return self.__verify_sig(proof, aggr_vk)

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
        g2, alpha, beta = aggr_vk
        h, _ = proof.sig
        c, ra, rr, rs = proof.zkp
        Va = c * proof.k + rr * g2 + (1 - c) * alpha  # For the attributes
        for i, attribute in enumerate(proof.attributes):
            if attribute == "":
                Va += ra[i] * beta[i]
        Vr = c * proof.vu + rr * h  # For the commitment r
        domain_hash = BpGroupHelper.G.hashG1(self.domain)
        Vid = proof.user_id * c + domain_hash * rs
        Vh = proof.h_secret * c + h * rs
        return c == helper.to_challenge([g1, g2, alpha, Va, Vr, Vid, Vh] + hs + beta)

    def __verify_sig(self, proof, aggr_vk):
        """
        Verify that everything in the sig is okay
        The user returned the correct commitment to all the attributes
        h is not 1
        Verifies the sig e(h, proof.k + aggr) * e(proof.h_secret, beta[-1]) != e(s + proof.vu, g2)
        And that the user is not in the banned list

        :param proof: The proof send by the client
        :param aggr_vk: The verification key
        :return: True if everything is okay False otherwise
        """
        G, g2, e = BpGroupHelper.G, BpGroupHelper.g2, BpGroupHelper.e
        (g2, _, beta) = aggr_vk
        # Add the public attributes in the k
        aggr = G2Elem.inf(G)
        for i, attribute in enumerate(proof.attributes):
            if attribute != "":
                aggr += Bn.from_binary(sha256(attribute).digest()) * beta[i]

        h, s = proof.sig
        if proof.attributes_commitment != proof.k + aggr:
            return False  # Means the user did not create the correct commitment for all the values
        if h.isinf():
            return False  # Check if h is 1
        if e(h, proof.k + aggr) * e(proof.h_secret, beta[-1]) != e(s + proof.vu, g2):
            return False  # Check if the sig is correct
        # Lastly check if the signature is banned
        if any(e(h, rev_sig) == e(proof.h_secret, beta[-1]) for rev_sig in ban_users.values()):
            return False
        return True
