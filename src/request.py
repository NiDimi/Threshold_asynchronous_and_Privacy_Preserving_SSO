class Request:
    def __init__(self, pk, C, cypher, zkp, attributes):
        self.users_pk = pk
        self.C = C
        self.cypher = cypher
        self.zkp = zkp
        self.attributes = attributes
