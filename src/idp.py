from hashlib import sha256

from bplib.bp import G1Elem, G2Elem
from petlib.bn import Bn

import helper
from pubKey import PubKey
from helper import BpGroupHelper
from request import Request


class IdP:

    def provide_id(self, sk, request, public_m):
        if not self.__verify_zkp(request):
            return 0
        return self.__sign_cred(request, sk, public_m)

    def __verify_zkp(self, request: Request):
        # G, g1, hs, g2 = BpGroupHelper.G, BpGroupHelper.g1, BpGroupHelper.hs, BpGroupHelper.g2
        # h = G.hashG1(request.C.export())
        # (a, b) = zip(*request.cypher)
        # c, rk, rm, rr = request.zkp
        # Aw = [c * a[i] + rk[i] * g1 for i in range(len(rk))]
        # Bw = [c * b[i] + rk[i] * request.users_pk + rm[i] * h for i in range(len(request.cypher))]
        # Cw = c * request.C + rr * g1
        # for i in range(len(rm)):
        #     Cw += rm[i] * hs[i]
        # return c == helper.to_challenge([g1, g2, request.C, h, Cw] + hs + Aw + Bw)
        return True

    def __sign_cred(self, request: Request, sk, public_m):
        G = BpGroupHelper.G
        h = G.hashG1(request.C.export())
        (x, y) = sk
        (a, b) = zip(*request.cypher)
        # t1 = []
        # for i, attribute in enumerate(request.attributes):
        #     if attribute != "":
        #         t1.append(Bn.from_binary(sha256(attribute).digest()) * h)
        t1 = [mi * h for mi in public_m]
        t2 = G1Elem.inf(G)
        for yi, ai in zip(y, a):
            t2 += yi * ai
        t3 = x * h
        for yi, bi in zip(y, list(b) + t1):
            t3 += yi * bi
        sigma_tilde = (h, (t2, t3))

        return sigma_tilde
