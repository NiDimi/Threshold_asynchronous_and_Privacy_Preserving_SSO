import sys
from typing import List, Tuple

sys.path.append("../src")

from helper import BpGroupHelper
from client import Client
from idp import IdP


def test_cred_issue(attributes):
    print("Testing with", len(attributes), "attributes")
    # First create the object for IdP
    idp = IdP(len(attributes))
    # We need to generate the keys that IdP is going to use and get the public to distribute to the IdP and RP
    pk = idp.keygen()

    # Initialize the client object
    client = Client(pk)
    # Create a request which is going to commit the secret attributes and create a ZKP about them
    request = client.request_id(attributes, b"Hello")

    # Pass the request created in the IdP in order to verify it and return the blinded signature
    sig_prime = idp.provide_id(request, b"Hello")

    # Check if the IdP managed to verify the ZKP
    if sig_prime == 0:
        print("Sign request failed")
        exit(1)
    # Unblind the signature
    sig = client.unbind_sig(sig_prime)
    # Check if the IdP provided a correctly formed signature
    if client.verify(sig, attributes):
        print("Successful Verification")
    else:
        print("The ublinded credential verification failed")
        exit(1)
    print("Testing Passed with", len(attributes), "attribute")


BpGroupHelper.setup()
attributes: List[Tuple[bytes, bool]] = [
    (b"secre1", True),
    (b"secre2", True),
    (b"plain1", False)]
# Test with 3 attributes
test_cred_issue(attributes)
# Test with 1 attribute
attributes: List[Tuple[bytes, bool]] = [
    (b"secre1", True)]

test_cred_issue(attributes)
