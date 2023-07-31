from helper import pack, unpack


class CredProof:
    def __init__(self, user_id, k, vu, sig, zkp, attributes, h_secret, attributes_commitment):
        """

        :param user_id: The users secret as the exponent of the domain of the RP used to create identity
        :param k: The commitment of the private attributes
        :param vu: Created using h of the sig and the randomness used for the commitment
        :param sig: The signature in the form (h, sig)
        :param zkp: The parameters necessary for to prove the zkp
        :param attributes: The attributes with the private hidden as ""
        :param h_secret: The users secret as the exponent of the h in the sig used for verification as the secret is in
        the sig
        :param attributes_commitment: All the attributes committed that we be used to open the deanonymize the user if
        needed. In a normal setting the RP would set that after adding the public atributes to the k.
        """
        self.user_id = user_id
        self.k = k
        self.vu = vu
        self.sig = sig
        self.zkp = zkp
        self.attributes = attributes
        self.h_secret = h_secret
        self.attributes_commitment = attributes_commitment

    def to_json(self):
        """
        Just packs the whole class
        :return: The packed class
        """
        return pack(self.__dict__)

    @classmethod
    def from_json(cls, data):
        return cls(**unpack(data))
