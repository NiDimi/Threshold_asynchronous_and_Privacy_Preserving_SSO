import sys
from typing import List, Tuple

from binascii import hexlify
from json import loads, dumps

import requests
from petlib.bn import Bn

sys.path.append("../src")
import helper
from helper import BpGroupHelper, pack, unpack
from client import Client
from idp import IdP, setup_idps
from rp import RP
from opener import Opener, check_sig, deanonymize

"""
Code strongly inspired by https://github.com/asonnino/coconut-timing
"""

# Static fields
SERVER_ADDR = [
    "ec2-13-41-165-172.eu-west-2.compute.amazonaws.com",
    "ec2-18-168-72-172.eu-west-2.compute.amazonaws.com",
    "ec2-18-134-76-159.eu-west-2.compute.amazonaws.com",
    "ec2-18-169-119-204.eu-west-2.compute.amazonaws.com",
]

ROUTE_SERVER_INFO = "/"
ROUTE_IDP_SET = "/idp/set"
ROUTE_IDP_PROVIDEID = "/idp/provideid"
ROUT_RP_VERIFYID = "/rp/verifyid"

"""
------------------------------------ Functions ---------------------------------------------------------
"""


def test_connection():
    """
    Test the connection to the server
    """
    for server in SERVER_ADDR:
        url = "http://" + server + ":" + str(80) + ROUTE_SERVER_INFO
        print("Sending test connection request to", url)
        r = requests.get(
            url
        )
        assert loads(r.text)["status"] == "OK"


def set_idp_keys(idps, aggr_vk):
    """
    Since we are in a normal scenario using secret sharing to create the IdP keys we emulate that from here andd give to
    the idps their keys

    :param aggr_vk: The aggregated verification key
    :param idps: A list with IdPs that hold their keys
    """
    for i, server in enumerate(SERVER_ADDR):
        url = "http://" + server + ":" + str(80) + ROUTE_IDP_SET
        data = dumps({
            "sk": pack(idps[i].sk),
            "vk": pack(idps[i].vk),
            "aggr_vk": pack(aggr_vk),
        })
        print("Setting the idp keys", url, data)
        r = requests.post(
            url,
            data
        )
        assert loads(r.text)["status"] == "OK"


def client_request_id(request):
    """
    Send a request to the IdP servers for a sig

    :return: the list of the sigs from the IdP
    """
    json = {"request": request.to_json()}
    sigs = []
    for server in SERVER_ADDR:
        url = "http://" + server + ":" + str(80) + ROUTE_IDP_PROVIDEID
        data = dumps(json)
        print("Sending request for signature to the IdP", url, data)
        r = requests.post(
            url,
            data
        )
        assert loads(r.text)["status"] == "OK"
        sig = unpack(loads(r.text)["load"])
        sigs.append(sig)
    return sigs


def send_proof(proof):
    """
    Sends proof of posession of credentials to the RP

    :param proof: The proof of the client
    """
    json = {"proof": proof.to_json()}
    url = "http://" + SERVER_ADDR[0] + ":" + str(80) + ROUT_RP_VERIFYID
    data = dumps(json)
    print("Sending proof to the RP", url, data)
    r = requests.post(
        url,
        data
    )
    print(loads(r.text))
    assert loads(r.text)["status"] == "OK"


"""
------------------------------------ start of the program ---------------------------------------------------------
"""
if __name__ == "__main__":
    # Simply test the connection
    test_connection()
    print("Test connection: OKAY")
    # We need to create the IdP keys here. Basically emulate the secret sharing protocol
    BpGroupHelper.setup(3)
    idps = setup_idps(3, 4)
    # Get the aggregate vk
    vk = [idp.vk for idp in idps]
    aggr_vk = helper.agg_key(vk)
    set_idp_keys(idps, aggr_vk)  # Send to each IdP server the key generated when emulating the ss
    print("Keys set: OKAY")

    # Sending id request to the IdP
    attributes: List[Tuple[bytes, bool]] = [
        (b"hidden1", True),
        (b"hidden2", True),
        (b"public1", False)]
    client = Client(attributes, aggr_vk)
    # We don't really care about the openers, so we pass arbitrary values
    openers = [Opener() for _ in range(2)]
    request = client.request_id(1, openers)
    sigs_prime = client_request_id(request)
    print("Sig: RECEIVED")

    # Aggregate the sigs
    sigs = [client.unbind_sig(sig_prime) for sig_prime in sigs_prime]
    sigs[-1] = None
    client.agg_cred(sigs)
    assert client.verify_sig()

    proof = client.prove_id(b"Domain")
    send_proof(proof)
    print("Proof: VALIDATED")
