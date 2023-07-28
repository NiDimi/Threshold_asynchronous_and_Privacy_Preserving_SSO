class Request:
    def __init__(self, user_id, pk, C, cypher, zkp, attributes, opening_c, h_secret):
        self.user_id = user_id
        self.users_pk = pk
        self.C = C
        self.cypher = cypher
        self.zkp = zkp
        self.attributes = attributes
        self.opening_c = opening_c
        self.h_secret = h_secret
