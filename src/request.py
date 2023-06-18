class Request:
    def __init__(self, C, c, r, attributes):
        """
        The request that the user sents to the IdP

        :param C: The commitment of the values the user wants to keep private
        :param c: The challenge created in a NIZKP
        :param rs: The repsonse of when creating a NIZKP
        :param attributes: The attributes that the user sends.
        IMPORTANT empty strings represent private attributes
        """
        self.C = C
        self.c = c
        self.r = r
        self.attributes = attributes
