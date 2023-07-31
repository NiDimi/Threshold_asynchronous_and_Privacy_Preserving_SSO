from helper import pack, unpack


class Request:
    def __init__(self, user_id, users_pk, Cm, cypher, zkp, attributes, opening_params, h_secret):
        """
        The request the client sends to the IdP's for the credentials

        :param user_id: The user_id that is requesting the credential
        :param pk: Its public key in order to verify the knowledge of sk
        :param Cm: The commitment of all the attributes
        :param cypher: The encrypted el gamal of the attributes in the form (a, b)
        :param zkp: The zero knowledge proof necessary parameters
        :param attributes: The attributes with the private attributes removed as ""
        :param opening_params: The parameters necessary to open the signature and verify it
        :param h_secret: h^user_secret used for the signature in order to be able to deanonymize the user
        """
        self.user_id = user_id
        self.users_pk = users_pk
        self.Cm = Cm
        self.cypher = cypher
        self.zkp = zkp
        self.attributes = attributes
        self.opening_params = opening_params
        self.h_secret = h_secret

    def to_json(self):
        """
        Just packs the whole class
        :return: The packed class
        """
        return pack(self.__dict__)

    @classmethod
    def from_json(cls, data):
        return cls(**unpack(data))
