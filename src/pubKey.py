class PubKey:
    def __init__(self, g1, g2, X, Yg1, Yg2):
        """
        Constructor for the public key that has all the necessary elements

        :param g1: Generator of group G1
        :param g2: Generator of group G2
        :param X: g2 ^x public key X
        :param Yg1: g1 ^yi public keys Y in group G1
        :param Yg2: g2 ^yi public keys Y in group G2
        """
        self.g1 = g1
        self.g2 = g2
        self.X = X
        self.Yg1 = Yg1
        self.Yg2 = Yg2
