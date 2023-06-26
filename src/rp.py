from hashlib import sha256

from petlib.bn import Bn

from pubKey import PubKey
from credproof import CredProof
import helper
from helper import BpGroupHelper


class RP:
    def __init__(self, idp_pk):
        self.__idp_pk: PubKey = idp_pk

    def verify_id(self, proof: CredProof, domain):
        """
        Implementation of Section 6.2 of the paper
        Short Randomizable Signatures the verifier side
        https://doi.org/10.1007/978-3-319-29485-8_7

        :param proof: The proof the user generated to prove his credentials
        :param domain: The domain of the RP
        :return: True if the signature is verified false otherwise
        """
        if not self.__verify_zkp(proof, domain):
            return False

        final_pi = self.__create_final_pi(proof.pi, proof.attributes)
        sig1, sig2 = proof.sig
        return not sig1.isinf() and BpGroupHelper.e(sig1, final_pi) == BpGroupHelper.e(sig2,
                                                                                       self.__idp_pk.g2)

    def __verify_zkp(self, proof: CredProof, domain):
        """
        Verify that the clients NIZKP request is correct
        Vpi = pi ^ c * g2 ^ rt * Yg2[0] ^ rs * Yg2[i+1] ^ ri
        vid = user_id ^ c * H(domain) ^ rs
        True if hash(pi || id || Vpi || Vid) = c

        :param proof: The proof the user generated to prove his credentials
        :param domain: The domain of the RP
        :return: true if the zkp can be verified false otherwise
        """
        # Prepare Vpi
        Vpi = proof.pi * proof.c + self.__idp_pk.g2 * proof.r[0] + self.__idp_pk.Yg2[0] * proof.r[1]
        j = 2
        for i, attribute in enumerate(proof.attributes):
            if attribute == "":
                Vpi += self.__idp_pk.Yg2[i+1] * proof.r[j]
                j += 1
        # Prepare Vid
        domain_hash = BpGroupHelper.G.hashG1(domain)
        Vid = proof.user_id * proof.c + domain_hash * proof.r[1]
        # Do the final check
        return proof.c == helper.to_challenge(
            [proof.pi.export(), proof.user_id.export(), Vpi.export(), Vid.export()])

    def __create_final_pi(self, pi, attributes):
        """
        Add to the proof pi the public values (including the public key X). The client has only added the private values
        pi += X * Yg2[i+1] ^ hash(attributei)

        :param pi: The proof pi with only the private attributes
        :param attributes: All the attributes. Empty strings are placeholders for private attributes
        :return: The pi with all the attributes
        """
        final_pi = pi + self.__idp_pk.X
        for i, attribute in enumerate(attributes):
            if attribute == "":
                continue
            final_pi += self.__idp_pk.Yg2[i+1] * Bn.from_binary(sha256(attribute).digest())
        return final_pi
