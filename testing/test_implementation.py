import sys
from typing import List, Tuple
import pytest
from pytest import raises

sys.path.append("../src")

from helper import BpGroupHelper
from client import Client
from idp import IdP
from rp import RP

attributes: List[Tuple[bytes, bool]] = [
    (b"secre1", True),
    (b"secre2", True),
    (b"plain1", False)]
attribute: List[Tuple[bytes, bool]] = [
    (b"secre1", True)]
BpGroupHelper.setup()


def test_idp_keygen():
    pk = IdP(1).keygen()
    assert pk is not None
    pk_new = IdP(1).keygen()
    assert pk != pk_new


@pytest.mark.parametrize("config", [attributes, attribute])
def test_idp_client(config):
    idp = IdP(len(config))
    pk = idp.keygen()
    client = Client(pk)
    request = client.request_id(config, b"Data")
    sig_prime = idp.provide_id(request, b"Data")
    assert sig_prime != 0
    sig = client.unbind_sig(sig_prime)
    assert client.verify_sig(sig, config)
    bad_request = client.request_id(config, b"data")
    sig_prime = idp.provide_id(bad_request, b"Data")
    assert sig_prime == 0


@pytest.mark.parametrize("config", [attributes, attribute])
def test_complete_implementation(config):
    bad_attributes: List[Tuple[bytes, bool]] = [
        (b"secre12", True),
        (b"secre2", True),
        (b"plain1", False)]
    # ------------------ Idp - Client  ------------------
    # First create the object for IdP
    idp = IdP(len(attributes))
    # We need to generate the keys that IdP is going to use and get the public to distribute to the IdP and RP
    pk = idp.keygen()

    # Initialize the client object
    client = Client(pk)
    # Create a request which is going to commit the secret attributes and create a ZKP about them
    request = client.request_id(attributes, b"Data")

    # Pass the request created in the IdP in order to verify it and return the blinded signature
    sig_prime = idp.provide_id(request, b"Data")

    # Check if the IdP managed to verify the ZKP
    assert sig_prime != 0
    # Unblind the signature
    sig = client.unbind_sig(sig_prime)
    # Check if the IdP provided a correctly formed signature
    assert client.verify_sig(sig, attributes)

    # Test bad attributes
    assert not client.verify_sig(sig, bad_attributes)

    # ------------------ RP - Client  ------------------
    # Generate the proof that it will be sent to the RP to prove knowledge
    proof = client.prove_id(sig, attributes, b"Data", b"Domain")

    # Initialize the RP object
    rp = RP(pk)
    # Verify the user
    assert rp.verify_id(proof, b"Data", b"Domain")

    # Test bad proof
    bad_proof = client.prove_id(sig_prime, attributes, b"Data", b"Domain")
    assert not rp.verify_id(bad_proof, b"Data", b"Domain")
    bad_proof_2 = client.prove_id(sig, bad_attributes, b"Data", b"Domain")
    assert not rp.verify_id(bad_proof_2, b"Data", b"Domain")
