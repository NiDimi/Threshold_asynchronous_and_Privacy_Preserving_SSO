class Request:
    def __init__(self, C, c, r, attributes):
        """
        The request that the user sents to the IdP

        :param C: The commitment of the users secret
        :param c: The challenge created in a NIZKP
        :param r: The responses of when creating a NIZKP. It holds (rt, rs)
        :param attributes: The public attributes that the user wants to sign
        """
        self.C = C
        self.c = c
        self.r = r
        self.attributes = attributes
