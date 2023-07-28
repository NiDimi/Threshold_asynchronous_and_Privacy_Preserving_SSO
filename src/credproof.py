class CredProof:
    def __init__(self, user_id, k, vu, sig, zkp, attributes, key_commitment, attributes_commitment):
        self.user_id = user_id
        self.k = k
        self.vu = vu
        self.sig = sig
        self.zkp = zkp
        self.attributes = attributes
        self.key_commitment = key_commitment
        self.attributes_commitment = attributes_commitment

