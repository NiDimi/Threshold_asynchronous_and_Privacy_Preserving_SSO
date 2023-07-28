from hashlib import sha256

from bplib.bp import G1Elem, G2Elem
from petlib.bn import Bn

import helper
from helper import BpGroupHelper, ElGamal, Polynomial
from request import Request
from credproof import CredProof


class Client:
    def __init__(self, attributes, vk):
        assert len(attributes) <= len(BpGroupHelper.hs)
        self.__elgamal = ElGamal(BpGroupHelper.g1)
        self.__attributes = attributes
        #  The hashed attributes in the style (hash, True/False) indicating private or not
        self.__hashed_attributes = helper.hash_attributes(attributes)
        self.__aggr_vk = vk
        self.__sig = None
        self.__sk = BpGroupHelper.o.random()
        self.__id = BpGroupHelper.o.random()

    def request_id(self, to, openers):
        G, o, g1 = BpGroupHelper.G, BpGroupHelper.o, BpGroupHelper.g1
        C, r = self.__create_commitment()

        h = G.hashG1(C.export())
        # El-gamal encryption
        enc = self.__encrypt_elgamal(h)
        (a, b, k) = zip(*enc)
        cypher = list(zip(a, b))
        # ZKP
        pi_s = self.__create_zkp_idp(self.__elgamal.pk, C, k, r, h)
        public_attributes = ["" if attr[1] else attr[0] for attr in self.__attributes]
        c_opening = self.opening_setup(to, openers)
        return Request(self.__id, self.__elgamal.pk, C, cypher, pi_s, public_attributes, c_opening, h * self.__sk)

    def __encrypt_elgamal(self, h):
        """
        Encrypt the attributes using el-gamal in order to take advantage of its homomorphic properties
        enc_i = g1^k_i, pk^k_i * h ^ attribute_i

        :param h: Hash(C) where C is the commitment of the attributes
        :return: enc list in the style (a_i, b_i, randomness used k_i)
        """
        enc = []
        for i, attribute in enumerate(self.__hashed_attributes):
            if attribute[1]:
                enc.append(self.__elgamal.encrypt(attribute[0] * h))
        return enc

    def __create_commitment(self):
        """
        Create the commitment of the attributes in order to generate a similar base for the IdP
        C = g1^r * h_i^attribute_i

        :return: The commitment and the randomness use to create it
        """
        o, g1, hs = BpGroupHelper.o, BpGroupHelper.g1, BpGroupHelper.hs
        r = o.random()
        C = r * g1
        for i, attribute in enumerate(self.__hashed_attributes):
            C += attribute[0] * hs[i]
        return C, r

    def __create_zkp_idp(self, pk, C, k, r, h):
        """
        Create the ZKP for the randomness r used for the commitment, for the whole commitment, and for elgamal enc
        Va: For the elgamal encryptiono first part = g1^random_k_i
        Vb: For the elgamal encryption second part = pk^random_k_i * h^random_pa_i
        Vc: For the commitment = g1^random_t * h_i ^random_a_i
        random_a_i and random_pa_i is the same but in the el gamal only the private attrubutes were used thats the diff
        c = Hash(g1 || g2 || C || h || Vc || hs || Va || Vb)
        rr = random_t - c * r
        rk = random_k_i - c * k_i
        ra = random_a_i - c * attribute_i

        :param pk: The public key used for el gamal encryption
        :param C: The commitment of the attributes
        :param k: The randomness used for the el gamal encryption
        :param r: The randomness used for the commitment
        :param h: The HashG1(C) that was used for the el gamal encryption
        :return: the responses rr,rk,ra and the challenge c see above
        """
        o, g1, hs, g2 = BpGroupHelper.o, BpGroupHelper.g1, BpGroupHelper.hs, BpGroupHelper.g2
        # Compute witnesses
        wr = o.random()  # Randomness for the r in the commitment
        wk = [o.random() for _ in k]  # Randomness for the randomness k in el gamal
        wa = [o.random() for _ in self.__attributes]  # Randomness for the attributes
        # Compute the commitments
        Va = [g1 * wki for wki in wk]  # For the elgamal encryption the alpha
        Vb = []  # For the elgamal encryption the beta
        Vc = wr * g1  # For the commitment of the attributes (C)
        for i, attribute in enumerate(self.__attributes):
            if attribute[1]:
                Vb.append(wk[i] * pk + wa[i] * h)
            Vc += wa[i] * hs[i]
        # Compute the challenge
        c = helper.to_challenge([g1, g2, C, h, Vc] + hs + Va + Vb)
        # Compute the responses
        rr = (wr - c * r) % o  # response for the r randomness
        rk = [(wk[i] - c * k[i]) % o for i in range(len(wk))]  # response for the k's randomness
        ra = [(wa[i] - c * self.__hashed_attributes[i][0]) % o for i in range(len(wa))]  # response for the attributes
        return c, rk, ra, rr

    def opening_setup(self, to, openers):
        """
        Set up the C's required for the opening operation basically implementing shamir secret sharing
        c0 = g2 ^ random
        c1 = opener.public_key ^ random * s_i ^ g_q+1
        where s_i is the share of the secret sk

        :param to: The threshold necessary for the opening
        :param openers: A list with all the openers
        :return: the c as a dict in the format (i, [c0, c1])
        """
        o, g2 = BpGroupHelper.o, BpGroupHelper.g2,
        no = len(openers)
        coeff = [o.random() for _ in range(to - 1)]
        coeff.insert(0, self.__sk)  # We add as the first coefficient the secret sk which we want to hide
        c = {}
        for i in range(1, no + 1):
            s = Polynomial.evaluate(coeff, i)
            r = o.random()
            c0 = g2 * r
            _, _, b = self.__aggr_vk
            c1 = openers[i - 1].pk * r + b[-1] * s
            c[i] = (c0, c1)
        return c

    def unbind_sig(self, sig_prime):
        """
        Unblind the blinded sig which is basically is decrypting with el gamal

        :param sig_prime: The encrypted signature
        :return: The unblinded signature
        """
        h, c_prime = sig_prime
        sig = h, self.__elgamal.decrypt(c_prime)
        return sig

    def agg_cred(self, sigs):
        """
        Aggregate all the credentials generated from the different IdP and store it in sig

        :param sigs: A list of the signatures
        """
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
        self.__sig = h[0], aggr_sig

    def verify_sig(self):
        """
        Verify the generation of the signature from the IdP and the aggregation
        e(h, b_i ^ attribute_i) = e(s, g2)

        :return: True if it is correct false otherwise
        """
        e = BpGroupHelper.e
        g2, alpha, beta = self.__aggr_vk
        h, s = self.__sig
        verification_result = alpha + beta[-1] * self.__sk
        for i, attribute in enumerate(self.__hashed_attributes):
            verification_result += beta[i] * attribute[0]
        return not h.isinf() and e(h, verification_result) == e(s, g2)

    def prove_id(self, rp_domain):
        domain_hash = BpGroupHelper.G.hashG1(rp_domain)
        user_id = domain_hash * self.__sk
        # Randomise the sig
        h_prime, s_prime = self.__randomize_signature()
        sig_prime = h_prime, s_prime
        # Create the K
        k, r, attribute_commitment = self.__commit_values()
        # Create the vu
        vu = r * h_prime
        # ZKP
        pi_v = self.__create_zkp_rp(sig_prime, r)
        public_attributes = ["" if attr[1] else attr[0] for attr in self.__attributes]
        return CredProof(user_id, k, vu, sig_prime, pi_v, public_attributes, h_prime * self.__sk, attribute_commitment)

    def __randomize_signature(self):
        """
        Randomizes the signature to provide unlinkability
        sig_prime  = h^r, s^r

        :return: A randomized signature of the client
        """
        o = BpGroupHelper.o
        r = o.random()
        h, s = self.__sig
        return h * r, s * r

    def __commit_values(self):
        """
        Create k in order to hide the private attributes and to prove correct form of the vk
        k = a * g2^r * b_i^priv_attribute_i
        attributes_commitment = k * b_i^pub_attribute_i

        :return: The k created and the randomness it was to create it
        """
        G, o = BpGroupHelper.G, BpGroupHelper.o
        g2, alpha, beta = self.__aggr_vk
        r = o.random()
        k = alpha
        attribute_commitment = G2Elem.inf(G)
        for i, attribute in enumerate(self.__hashed_attributes):
            if attribute[1]:
                k += attribute[0] * beta[i]
            else:
                attribute_commitment += attribute[0] * beta[i]
        k += r * g2
        attribute_commitment += k
        return k, r, attribute_commitment

    def __create_zkp_rp(self, sig, r):
        """
        Create the ZKP for the randomness r used to create k, for knowledge of the private attribtues
        and correct construction of the vk
        Vr = h^random_r
        Va = alpha * beta_i^random_a_i * g2 ^ random_r
        c = (g1 || g2 || alpha || Va || Vr || hs || beta)
        rr = randdom_r - c * r
        ra = random_a_i - c * attribute_i

        :param sig: The randomized signature that will be sent to the RP
        :param r: The randdomness used to create k
        :return: The responses rr, ra and the challenge c see above
        """
        G, o, g1, hs = BpGroupHelper.G, BpGroupHelper.o, BpGroupHelper.g1, BpGroupHelper.hs
        (g2, alpha, beta) = self.__aggr_vk
        (h, _) = sig
        # Create witnesses and commitments
        wr = o.random()  # Witness for the r
        Vr = wr * h  # The commitment for the r
        wa = []  # Witness for the attributes
        Va = wr * g2 + alpha  # Witness for the attributes and key
        for i, attribute in enumerate(self.__attributes):
            if attribute[1]:
                wa.append(o.random())
                Va += wa[i] * beta[i]
        # Compute the challenge
        c = helper.to_challenge([g1, g2, alpha, Va, Vr] + hs + beta)
        # Compute the responses
        ra = [(wmi - c * attribute[0]) % o for wmi, attribute in zip(wa, self.__hashed_attributes) if wmi is not None]
        rr = (wr - c * r) % o
        return c, ra, rr
