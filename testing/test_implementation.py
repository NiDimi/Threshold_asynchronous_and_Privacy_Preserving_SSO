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
from opener import Opener, check_sig, deanonymize


def test_idp_client_normal():
    # Set up phase
    threshold_idp = 2
    total_idp = 5
    threshold_opener = 2
    total_opener = 3
    BpGroupHelper.setup(5)
    # Generate the entities in the protocol
    idps = setup_idps(threshold_idp, total_idp)
    openers = [Opener() for _ in range(total_opener)]

    attributes: List[Tuple[bytes, bool]] = [
        (b"hidden1", True),
        (b"hidden2", True),
        (b"public1", False),
        (b"hidden3", True)]
    attributes = helper.sort_attributes(attributes)
    vk = [idp.vk for idp in idps]
    vk[0] = None
    aggr_vk = helper.agg_key(vk)
    client = Client(attributes, aggr_vk)
    request = client.request_id(threshold_opener, openers)
    sigs_prime = [idp.provide_id(request) for idp in idps]
    sigs = [client.unbind_sig(sig_prime) for sig_prime in sigs_prime]
    sigs[1] = sigs[4] = None
    client.agg_cred(sigs)
    assert client.verify_sig()
    proof = client.prove_id(b"Domain")
    assert RP().verify_id(proof, aggr_vk)

    # Ban user
    assert deanonymize(openers, proof, aggr_vk) == request.user_id

    # Check again
    assert not RP().verify_id(proof, aggr_vk)


