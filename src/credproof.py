class CredProof:
    def __init__(self, sig, pi, user_id, c, r, attributes):
        """
        Contrustructor for the proof to the RP that the user posses the credentials to

        :param sig: The signature that was created from the IdP but randomized
        :param pi: Proof in ZKP that is useed for verification on the signatures
        :param user_id: The user ID that will be used by the RP and for the NIZKP
        :param c: The challenge created in a NIZKP
        :param r: The responses of when creating a NIZKP
        :param attributes: The public attributes that the user sends.
        IMPORTANT empty strings represent private attributes
        """
        self.sig = sig
        self.pi = pi
        self.user_id = user_id
        self.c = c
        self.r = r
        self.attributes = attributes
