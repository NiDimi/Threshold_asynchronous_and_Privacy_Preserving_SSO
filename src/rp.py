from hashlib import sha256

from petlib.bn import Bn

from pubKey import PubKey
from credproof import CredProof
import helper
from helper import BpGroupHelper


class RP:
    def __init__(self, idp_pk):
        self.__idk_pk: PubKey = idp_pk

    def verify_id(self, proof: CredProof, data, domain):
        """
        Implementation of Section 6.2 of the paper
        Short Randomizable Signatures the verifier side
        https://doi.org/10.1007/978-3-319-29485-8_7

        :param proof: The proof the user generated to prove his credentials
        :param data: data used for the NIZK verification (like time stamp etc.)
        :param domain: The domain of the RP
        :return: True if the signature is verified false otherwise
        """
        if not self.__verify_zkp(proof, data, domain):
            return False

        final_pi = self.__create_final_pi(proof.pi, proof.attributes)
        sig1, sig2 = proof.sig
        return not sig1.isinf() and BpGroupHelper.e(sig1, final_pi) == BpGroupHelper.e(sig2,
                                                                                       self.__idk_pk.g2)

    def __verify_zkp(self, proof: CredProof, data, domain):
        """
        Verify that the clients NIZKP request is correct
        Vpi = pi^c * X ^(1-c) * g2^ r1 * Yg2i^r2i
        Vid = H(domain) ^ rs
        True if hash(pi || id || Vpi || Vid || data) = c

        :param proof: The proof the user generated to prove his credentials
        :param data: data used for the NIZK verification (like time stamp etc.)
        :param domain: The domain of the RP
        :return: true if the zkp can be verified false otherwise
        """
        # Prepare Vpi
        Vpi = proof.pi * proof.c
        Vpi += self.__idk_pk.g2 * proof.r[0]
        Vpi += self.__idk_pk.X * (1 - proof.c)
        j = 1
        for i, attribute in enumerate(proof.attributes):
            if attribute == "":
                Vpi += self.__idk_pk.Yg2[i] * proof.r[j]
                j += 1
        # Prepare Vid
        Vid = proof.user_id * proof.c
        domain_hash = BpGroupHelper.G.hashG1(domain)
        # CHANGE HERE WITH THE RANDOMNESS OF THE SECRET S
        Vid += domain_hash * proof.r[1]
        # Do the final check
        return proof.c == helper.to_challenge(
            [proof.pi.export(), proof.user_id.export(), Vpi.export(), Vid.export(), data])

    def __create_final_pi(self, pi, attributes):
        """
        Add to the proof pi the public values. The client has only added the private values.
        pi += Yg2i * hash(attributei)

        :param pi: The proof pi with only the private attributes
        :param attributes: All the attributes. Empty strings are placeholders for private attributes
        :return: The pi with all the attributes
        """
        final_pi = pi
        for i, attribute in enumerate(attributes):
            if attribute == "":
                continue
            final_pi += self.__idk_pk.Yg2[i] * Bn.from_binary(sha256(attribute).digest())
        return final_pi
