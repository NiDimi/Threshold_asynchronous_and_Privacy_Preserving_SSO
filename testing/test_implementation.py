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
    attributes: List[Tuple[bytes, bool]] = [
        (b"hidden1", True),
        (b"hidden2", True),
        (b"public1", False),
        (b"hidden3", True)]
    BpGroupHelper.setup(len(attributes))
    # Generate the entities in the protocol
    idps = setup_idps(threshold_idp, total_idp)
    openers = [Opener() for _ in range(total_opener)]

    attributes = helper.sort_attributes(attributes)
    vk = [idp.vk for idp in idps]
    # Remove one of the key for testing, we need just the threshold not all
    vk[0] = None
    aggr_vk = helper.agg_key(vk)
    client = Client(attributes, aggr_vk)
    # Communication with Client - IdP
    request = client.request_id(threshold_opener, openers)
    sigs_prime = [idp.provide_id(request, aggr_vk) for idp in idps]
    sigs = [client.unbind_sig(sig_prime) for sig_prime in sigs_prime]
    # Hide some sigs so we can test the threshold setting
    sigs[1] = sigs[4] = None
    # Creaate the aggregated signature which would be stored in the client
    client.agg_cred(sigs)
    assert client.verify_sig()
    # Communication with Client - RP
    rp = RP(b"Domain")
    proof = client.prove_id(rp.domain)
    assert rp.verify_id(proof, aggr_vk)

    # Ban user
    assert deanonymize(openers, proof, aggr_vk) == request.user_id
    # Remove opener to test the threshold setting
    openers.pop()

    # Check again
    assert not rp.verify_id(proof, aggr_vk)
