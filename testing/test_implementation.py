import sys
from typing import List, Tuple
import pytest
from pytest import raises

sys.path.append("../src")

import helper
from helper import BpGroupHelper
from client import Client
from idp import IdP
from rp import RP


# def test_idp_keygen():
#     pk = IdP(1).keygen()
#     assert pk is not None
#     pk_new = IdP(1).keygen()
#     assert pk != pk_new


def test_idp_client_normal():
    # idp = IdP(len(config))
    # pk = idp.keygen()
    # client = Client(pk, b"secret")
    # request = client.request_id(config)
    # assert request != 0
    # sig_prime = idp.provide_id(request)
    # assert sig_prime != 0
    # sig = client.unbind_sig(sig_prime)
    # assert client.verify_sig(sig, config)
    # attributes: List[Tuple[bytes, bool]] = [
    #     (b"hidden1", True),
    #     (b"hidden2", True)]
    private_m = [10] * 2
    public_m = [3] * 1
    t, n = 2, 3
    BpGroupHelper.setup(3)
    client = Client()
    request = client.request_id(private_m, public_m)
    (sk, vk) = helper.ttp_keygen(t, n)
    aggr_vk = helper.agg_key(vk)
    sigs_prime = [IdP().provide_id(ski, request, public_m) for ski in sk]
    sigs = [client.unbind_sig(sig_prime) for sig_prime in sigs_prime]
    sig = client.agg_cred(sigs)

    assert client.verify_sig(sig, aggr_vk, public_m, private_m)
    proof = client.prove_id(sig, private_m, aggr_vk)
    assert RP().verify_id(proof, aggr_vk, public_m)

# @pytest.mark.parametrize("config", [attribute, attributes])
# def test_idp_client_bad(config):
#     # Just so we won't modify attributes
#     config = config[:]
#     idp = IdP(len(config))
#     pk = idp.keygen()
#     client = Client(pk, b"secret")
#     config.append(
#         (b"hidden1111", True))
#     print(attribute)
#     request = client.request_id(config)
#     assert request == 0
#     config.pop()
#     bad_request = client.request_id(config)
#     config.pop()
#     request = client.request_id(config)
#     bad_request.C = request.C
#     sig_prime = idp.provide_id(bad_request)
#     assert sig_prime == 0
#
#
# @pytest.mark.parametrize("config", [attribute, attributes])
# def test_complete_implementation(config):
#     # ------------------ Idp - Client  ------------------
#     # First create the object for IdP
#     idp = IdP(len(config))
#     # We need to generate the keys that IdP is going to use and get the public to distribute to the IdP and RP
#     pk = idp.keygen()
#
#     # Initialize the client object
#     client = Client(pk, b"secret")
#     # Create a request which is going to commit the secret attributes and create a ZKP about them
#     request = client.request_id(config)
#
#     # Pass the request created in the IdP in order to verify it and return the blinded signature
#     sig_prime = idp.provide_id(request)
#
#     # Check if the IdP managed to verify the ZKP
#     assert sig_prime != 0
#     # Unblind the signature
#     sig = client.unbind_sig(sig_prime)
#     # Check if the IdP provided a correctly formed signature
#     assert client.verify_sig(sig, config)
#
#     # Test bad attributes
#     # assert not client.verify_sig(sig, bad_attributes)
#
#     # ------------------ RP - Client  ------------------
#     # Generate the proof that it will be sent to the RP to prove knowledge
#     proof = client.prove_id(sig, config, b"Domain")
#
#     # Initialize the RP object
#     rp = RP(pk)
#     # Verify the user
#     assert rp.verify_id(proof, b"Domain")
#
#     # ------------------ BAD PROOFS ------------------
#     bad_attributes: List[Tuple[bytes, bool]] = [
#         (b"hidden12222", True),
#         (b"hidden2", True),
#         (b"public1", False)]
#     bad_proof = client.prove_id(sig_prime, config, b"Domain")
#     assert not rp.verify_id(bad_proof, b"Domain")
#     bad_proof_2 = client.prove_id(sig, bad_attributes, b"Domain")
#     if len(config) == 1:
#         assert bad_proof_2 == 0
#     else:
#         assert not rp.verify_id(bad_proof_2, b"Domain")
