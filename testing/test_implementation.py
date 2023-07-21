import sys
from typing import List, Tuple
import pytest
from pytest import raises

sys.path.append("../src")

import helper
from helper import BpGroupHelper
from client import Client
from idp import IdP, setup_idps
from rp import RP


def test_idp_client_normal():
    threshold = 2
    total = 5
    BpGroupHelper.setup(6)
    idps = setup_idps(threshold, total)

    attributes: List[Tuple[bytes, bool]] = [
        (b"hidden1", True),
        (b"hidden2", True),
        (b"public1", False),
        (b"hidden2", True),]
    attributes = helper.sort_attributes(attributes)
    vk = [idp.vk for idp in idps]
    vk[0] = None
    aggr_vk = helper.agg_key(vk)
    client = Client(attributes, aggr_vk)
    request = client.request_id()
    sigs_prime = [idp.provide_id(request) for idp in idps]
    sigs = [client.unbind_sig(sig_prime) for sig_prime in sigs_prime]
    sigs[1] = sigs[4] = None
    client.agg_cred(sigs)
    assert client.verify_sig()
    proof = client.prove_id()
    assert RP().verify_id(proof, aggr_vk)
