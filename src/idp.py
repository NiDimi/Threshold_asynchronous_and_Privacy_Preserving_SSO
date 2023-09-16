from hashlib import sha256
from collections import defaultdict

from bplib.bp import G1Elem
from petlib.bn import Bn

import helper
from helper import BpGroupHelper, Polynomial
from request import Request
from opener import ledger


class IdP:
    def __init__(self, id, t, n):
        commitment_coeffs, s_shares, b_shares = self.generate_pedersen_vars(t, n)
        self.id = id
        self.commitment_coeffs = commitment_coeffs
        self.s_shares = s_shares
        self.b_shares = b_shares
        self.all_commitment_coeffs = {}
        self.all_shares = defaultdict(tuple)
        self.secret_share = None
        self.sk = [None, []]
        self.vk = ()

    """--------------------------CODE FOR THE GENERATION OF THE KEYS------------------------"""

    # The repo https://github.com/lovesh/secret-sharing-schemes was very helpful in coding the key generation

    def generate_pedersen_vars(self, t, n):
        """
        Generates two polynomials, the shares
        and creates the commitment g^s_i * h^t_i for i=0,...,threshold

        :param t: The minimum number of authorities we need (threshold)
        :param n: The total number of authorities we have
        :return: The committed coeffs, the shares of the secret, the shares of the blinding
        """
        g, h = BpGroupHelper.g_secret, BpGroupHelper.h_secret
        s_shares, s_coeff = self.generate_polynomial(t, n)  # Used for the secret
        b_shares, b_coeff = self.generate_polynomial(t, n)  # Blinding factor
        # create a dict with g^s_i * h^t_i. The broadcasted commitment
        commitment_coeffs = [g * s_coeff[i] + h * b_coeff[i] for i in range(t)]
        # Return the secret, the commitment coeffs, the shares of s and t
        return commitment_coeffs, s_shares, b_shares

    def generate_polynomial(self, t, n):
        """
        Generate a random polynomial.
        Also compute the shares s_j = f(j) for j=1,...,n

        :param t: The minimum number of authorities we need (threshold)
        :param n: The total number of authorities we have
        :return: The shares, and the coefficients
        """
        o = BpGroupHelper.o
        coeff = [o.random() for _ in range(t)]
        # Store the shares in the format {x(the value that it was evaluated at) : result)
        shares = {x: Polynomial.evaluate(coeff, x) for x in range(1, n + 1)}
        return shares, coeff

    def receive_share(self, sender_id, commitment_coeffs, share):
        """
        Just store the shares and the committed coeffs of the other IdP's.
        Each IdP needs to broadcast the commitment and the sharess

        :param sender_id: The id of the IdP that send the vars
        :param commitment_coeffs: The committed coeffs
        :param share: The shares in the style (s, b) - secret, blinding factor
        """
        self.all_commitment_coeffs[sender_id] = commitment_coeffs
        self.all_shares[sender_id] = share

    def verify_share(self, t, share, commitment_coeffs):
        """
        Each IdP needs to verify the share. If the check failed normally we would broadcast a complaint
        g^s * h^t = committed_coeffs_k^(id^k) for k=0,...,t

        :param t: The threshold
        :param share: The shares in the style (s, b) - secret, blinding factor
        :param commitment_coeffs: The committed coeffs
        :return: True if the verification works, false otherwise
        """
        assert len(commitment_coeffs) >= t
        g, h = BpGroupHelper.g_secret, BpGroupHelper.h_secret
        result_list = [commitment_coeffs[k] * (self.id ** k) for k in range(t)]
        result = G1Elem.inf(BpGroupHelper.G)
        for result_i in result_list:
            result += result_i
        return result == g * share[0] + h * share[1]

    def compute_final_secret(self, t, n):
        """
        For all participants final_s = Sum(all_shares_s), final_b = Sum(all_shares_b).
        We also add all the commitmetns in order to verify that the final secret is correct

        :param t: The minimum number of authorities we need (threshold)
        :param n: The total number of authorities we have
        """
        assert len(self.all_commitment_coeffs) == n - 1
        assert len(self.all_shares) == n - 1
        final_comm_coeffs = defaultdict(dict)
        for i in range(t):
            cm = G1Elem.inf(BpGroupHelper.G)
            for j in range(1, n + 1):
                # The final coefficient is only used for verification
                if j != self.id:
                    # Means different IdP take all the commitments
                    cm += self.all_commitment_coeffs[j][i]
                else:
                    # Means the same IdP take its commitment
                    cm += self.commitment_coeffs[i]
            final_comm_coeffs[i] = cm

        final_s_share = 0
        final_b_share = 0
        for i in range(1, n + 1):
            s, b = self.all_shares[i] if i != self.id else (self.s_shares[i], self.b_shares[i])
            # Summing the s and t
            final_s_share += s
            final_b_share += b
        # Verify that the final secret created is true
        assert self.verify_share(t, (final_s_share, final_b_share), final_comm_coeffs)
        self.secret_share = final_s_share

    """The keys of the idp will have the format sk = (x, y_1,...,y_q, y_q+1) and 
    vk = (g2, g2^x, g2^y_0,...,g2^y_q, g2^y_q+1) so we need to generate q+2 (1 x, q+1 y) shares and save it each time"""

    def save_sk_x(self):
        """
        Just save the x generated
        """
        self.sk[0] = self.secret_share

    def add_sk_y(self):
        """
        Add the y of the sk in the list
        """
        self.sk[1].append(self.secret_share)

    def generate_vk(self):
        """
        After collecting the hole sk we can now create the vk
        """
        g2 = BpGroupHelper.g2
        self.vk = (g2, self.sk[0] * g2, [g2 * y_i for y_i in self.sk[1]])

    """--------------------------CODE FOR THE PROTOCOL------------------------"""

    def provide_id(self, request, vk):
        """
        Provide a credential to the client

        :param request: The request of the user containing the necessary elements
        :param vk: The verification key
        :return: The credential if everything went correctly and 0 otherwise
        """
        G = BpGroupHelper.G
        h = G.hashG1(request.Cm.export())  # generate the common base with the user to add the public attributes
        if not self.__verify_zkp(request, h):
            return 0
        if not self.__verify_opening_proof(request.opening_params, request, vk, h):
            return 0
        return self.__sign_cred(request, h)

    def __verify_zkp(self, request: Request, h):
        """
        Verify the zkp created by the user
        Va = a_i^c * g1^rk_i
        Vb = b_i^c * pk^rk_i * h ^ ra_i
        Vc = C^c * g1^rr * h_i ^ ra_i
        Vs = h_secret^c * h^rs

        :param request: The request of the user containing the necessary elements
        :return: True if c = Hash(g1 || g2 || C || h || Vc || Vs || hs || Va || Vb) false otherwise
        """
        G, g1, hs, g2 = BpGroupHelper.G, BpGroupHelper.g1, BpGroupHelper.hs, BpGroupHelper.g2
        (a, b) = zip(*request.cypher)
        c, rk, ra, rr, rs = request.zkp
        # Compute the commitments
        Va = [c * a[i] + rk[i] * g1 for i in range(len(rk))]  # For the elgamal encryption the alpha
        # For the elgamal encryption the beta
        Vb = [c * b[i] + rk[i] * request.users_pk + ra[i] * h for i in range(len(request.cypher))]
        Vc = c * request.Cm + rr * g1  # For the commitment of the attributes (C)
        for i in range(len(ra)):
            Vc += ra[i] * hs[i]
        Vs = c * request.h_secret + h * rs
        return c == helper.to_challenge([g1, g2, request.Cm, h, Vc, Vs] + hs + Va + Vb)

    def __verify_opening_proof(self, opening_params, request, vk, h):
        """
        Verifies that the shares the user created for the secret is correct
        Vc0 = c0^c * g2^rr
        True if challenge = Hash(g2 || h || Vc0 || Vc1) and e(h_secret * h_coeff^(i^j), beta[-1]) = Vc1

        :param opening_params: The parameters used for the opening method
        :param request: The request of the user containing the necessary elements
        :param vk: The verification key
        :return: True if it is correct false otherwise
        """
        G, g2, e = BpGroupHelper.G, BpGroupHelper.g2, BpGroupHelper.e
        c, h_coeff = opening_params
        for i, c_i in enumerate(c.values()):
            c0, c1, proof = c_i
            challenge, rr, Vc1 = proof
            # ZKP for the c0
            Vc0 = challenge * c0 + g2 * rr
            coeffs_culculation = G1Elem.inf(G)
            _, _, beta = vk
            # Proof for the c1
            for j, coeffs in enumerate(h_coeff):
                coeffs_culculation += coeffs * ((i+1) * (j + 1))
            if helper.to_challenge([g2, h, Vc0, Vc1]) != challenge \
                    or Vc1 != e(request.h_secret + coeffs_culculation, beta[-1]):
                return False
        # Publish to the ledger the opening c's
        ledger[request.user_id] = c
        return True

    def __sign_cred(self, request: Request, h):
        """
        Basic PS signatures
        First we need to commit the public attributes since the user only commited the private C_pub = h^attributeP_i
        c_1 = a_j^y_i, c_2 = h^x * b_j ^ y_j * user_pk ^j_q+1

        :param request: The request of the user containing the necessary elements
        :param sk: The secret key of which to use to sign
        :return: the signature
        """
        G = BpGroupHelper.G
        # (x, y) = sk
        x, y = self.sk[0], self.sk[1]
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
        c_2 += request.h_secret * y[-1]
        return h, (c_1, c_2)


def simulate_secret_sharing(idps, t, n):
    """
    This function simulates the broadcast protocol of the secrets of the IdPs in order to generate the keys

    :param idps: The list of idps we have
    :param t: The minimum number of authorities we need (threshold)
    :param n: The total number of authorities we have
    :return: The idps with their share of the secret created
    """
    # Sharing its IdPs share with each other
    for i in range(n):
        for j in range(n):
            if i == j:  # Means we are in the same id participant so we just move on
                continue
            id, commitment_coeffs, s, b = idps[j].id, idps[j].commitment_coeffs, \
                idps[j].s_shares[i + 1], idps[j].b_shares[i + 1]
            # Verify the value meaning that no IdP is missbehaving
            assert idps[i].verify_share(t, (s, b), commitment_coeffs)
            idps[i].receive_share(id, commitment_coeffs, (s, b))
    # Every participant computes its share to the distributed secret.
    for i in range(n):
        idps[i].compute_final_secret(t, n)
    return idps


def setup_idps(t, n):
    """
    This function setups the IdPs and generates their sk and vk
    sk = (x, y_1,...,y_q, y_q)
    vk = (g2, g2^x, g2^y_0,...,g2^y_q, g2 ^y_q)
    So we neeed to exchange secrets to create x, and all the y's for the sk (q)
    And afterwards we can create the vk for all the IdP's

    :param t: The minimum number of authorities we need (threshold)
    :param n: The total number of authorities we have
    :return: The IdPs ready to run the SSO protocol
    """
    # Generating the IdPs
    idps = []
    for i in range(1, n + 1):
        idps.append(IdP(i, t, n))
    q = len(BpGroupHelper.hs)

    # Creating the x part of the sk
    idps = simulate_secret_sharing(idps, t, n)
    for i in range(n):
        # After sharing the secrets save their secret as the first part of the sk
        idps[i].save_sk_x()
        # And then make them generate new variables to re-share secrets for the y values
        idps[i].generate_pedersen_vars(t, n)

    # Creating the y's of the sk
    for j in range(q):
        idps = simulate_secret_sharing(idps, t, n)
        for i in range(n):
            idps[i].add_sk_y()
            idps[i].generate_pedersen_vars(t, n)

    # The sk is created so we need the vk of each IdP
    for i in range(n):
        idps[i].generate_vk()
    return idps
