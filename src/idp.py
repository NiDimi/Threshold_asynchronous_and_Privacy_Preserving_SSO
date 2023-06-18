from hashlib import sha256
from petlib.bn import Bn

import helper
from pubKey import PubKey
from helper import BpGroupHelper


class IdP:
    __group = BpGroupHelper()  # The group we will be using

    def __init__(self, num_attributes):
        """
        Constructor for the IdP

        :param num_attributes: The maximum number of attributes of the user
        """
        self.__sk = None  # The secret key
        self.__pk: PubKey = None  # The public key
        self.__num_attributes = num_attributes

    def keygen(self):
        """
        Generates the private and public keys
        Pick random (x, y1,....,y_num_attributes), compute sk = g1 ^ x and
        pk =(g1,g2,g2^x, g1^y1,...,g1^y_num_attributes, g2^y1,...,g2^y_num_attributes)

        :return: the public key
        """
        o, g1, g2 = BpGroupHelper.o, BpGroupHelper.g1, BpGroupHelper.g2
        x = o.random()
        # This is the private key
        self.__sk = g1 * x
        # Generating all the public keys for each message (attribute in our case)
        pkX = g2 * x
        Yg1 = []
        Yg2 = []
        for i in range(self.__num_attributes):
            y = o.random()
            Yg1.append(g1 * y)
            Yg2.append(g2 * y)

        self.__pk = PubKey(g1, g2, pkX, Yg1, Yg2)
        return self.__pk

    def provide_id(self, request, data):
        """
        Implementation of the 'Multi-Message Protocol' of the paper
        Short Randomizable Signatures the signer side
        https://doi.org/10.1007/978-3-319-29485-8_7

        :param request: The request generated by the client
        :param data: data used for the NIZK verification (like time stamp etc.)
        :return: the signature or zero if the ZKP verification failed
        """
        if not self.__verify_zkp(request, data):
            return 0
        return self.__sign_everything(request.C, request.attributes)

    def __verify_zkp(self, request, data):
        """
        Verify that the client NIZKP request is correct (Basically Schnorr NIZKP verification)
        V = C^c * g1^r0 * Yg1i ^ ri
        True if hash(C || V || data) = c

        :param request: The request generated by the client
        :param data: data used for the NIZK verification (like time stamp etc.)
        :return: true if it is correct false otherwise
        """
        # Prepare V
        V = request.C * request.c + self.__pk.g1 * request.r[0]  # The first randomness
        j = 1
        for i in range(len(request.attributes)):
            if request.attributes[i] == "":  # Means it is hidden, so we need to verify that the user knows the value
                V += self.__pk.Yg1[i] * request.r[j]
                j += 1
        # Do the final check
        return request.c == helper.to_challenge([request.C.export(), V.export(), data])

    def __sign_everything(self, user_commitment, attributes):
        """
        Prepare everything (both the plain and hidden attributes) and generate a blinded signature.
        commitment += Yg1i ^ H(public_attribute)

        :param user_commitment: The committed hidden attributes
        :param attributes: All the attributes. Empty strings are placeholders for secret attributes
        :return: The blinded signaturer
        """
        # We first need to also commit the plain attributes just so we can sign a single commitment with everything
        if len(attributes) == 1:  # Means we have only one hidden attribute which obviously is already committed
            return self.__sign_cred(user_commitment)
        # Start committing public attributes
        for i in range(len(attributes)):
            if attributes[i] == "": # Means plain
                continue
            hashed_attribute = Bn.from_binary(sha256(attributes[i]).digest())
            user_commitment += self.__pk.Yg1[i] * hashed_attribute
        return self.__sign_cred(user_commitment)

    def __sign_cred(self, commitment):
        """
        Sign the user's commitment
        blind_sig = g1^random, (sk * C)^random

        :param commitment: All the attributes committed
        :return: The PS signature
        """
        u = BpGroupHelper.o.random()
        return self.__pk.g1 * u, (self.__sk + commitment) * u
