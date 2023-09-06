import csv
import sys
import time
from typing import List, Tuple

from binascii import hexlify
from json import loads, dumps

import grequests
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
# SERVER_ADDR = [
#     "127.0.0.1",
# ]

ROUTE_SERVER_INFO = "/"
ROUTE_IDP_SET = "/idp/set"
ROUTE_IDP_PROVIDEID = "/idp/provideid"
ROUT_RP_VERIFYID = "/rp/verifyid"

ITERATIONS = 100

# timings
mem = []

total_idp = len(SERVER_ADDR)
threshold_idp = 1

"""
------------------------------------ Functions ---------------------------------------------------------
"""


def get_t_number(numbers):
    sorted_numbers = sorted(numbers)
    return sorted_numbers[threshold_idp - 1]


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


def async_request(route, json):
    unsent_request = [
        grequests.post(
            "http://" + addr + ":" + str(80) + route,
            data=dumps(json)
        )
        for addr in SERVER_ADDR
    ]
    responses = grequests.map(unsent_request, size=len(SERVER_ADDR))
    sigs = []
    numbers = []
    for r in responses:
        assert loads(r.text)["status"] == "OK"
        sig = unpack(loads(r.text)["load"])
        sigs.append(sig)
        numbers.append(r.elapsed.total_seconds())
    elapsed_time = get_t_number(numbers)
    mem.append({'time': elapsed_time})

    return sigs


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
    return async_request(ROUTE_IDP_PROVIDEID, json)


def send_proof(proof):
    """
    Sends proof of posession of credentials to the RP

    :param proof: The proof of the client
    """
    json = {"proof": proof.to_json()}
    unsent_request = [grequests.post(
        f"http://{SERVER_ADDR[0]}:80{ROUT_RP_VERIFYID}",
        data=dumps(json))]
    responses = grequests.map(unsent_request, size=1)
    for r in responses:
        assert loads(r.text)["status"] == "OK"
        mem.append({'time': r.elapsed.total_seconds()})
    return True


def save_idp():
    with open("latency_idp.csv", mode="a", newline="") as file:
        fieldnames = ["Threshold", "Time"]
        writer = csv.DictWriter(file, fieldnames)
        writer.writeheader()
        for i in range(len(mem)):
            writer.writerow({fieldnames[0]: threshold_idp, fieldnames[1]: mem[i]["time"] * 1000}, )


def save_rp():
    with open("latency_rp.csv", mode="w", newline="") as file:
        fieldnames = ["Time"]
        writer = csv.DictWriter(file, fieldnames)
        writer.writeheader()
        for i in range(len(mem)):
            writer.writerow({fieldnames[0]: mem[i]["time"] * 1000}, )


"""
------------------------------------ start of the program ---------------------------------------------------------
"""
if __name__ == "__main__":
    attributes: List[Tuple[bytes, bool]] = [
        (b"hidden1", True),
        (b"hidden2", True),
        (b"hidden3", True),
        (b"public1", False)]
    # Simply test the connection
    test_connection()
    print("Test connection: OKAY")
    # We need to create the IdP keys here. Basically emulate the secret sharing protocol
    BpGroupHelper.setup(len(attributes))
    total_opener = 3
    threshold_opener = 2
    for i in range(1, total_idp + 1):
        threshold_idp = i

        idps = setup_idps(1, total_idp)
        # Get the aggregate vk
        vk = [idp.vk for idp in idps]
        aggr_vk = helper.agg_key(vk)
        set_idp_keys(idps, aggr_vk)  # Send to each IdP server the key generated when emulating the ss
        print("Keys set: OKAY")
        del mem[:]
        print("Starting with IdPs:", threshold_idp)

        # Sending id request to the IdP
        client = Client(attributes, aggr_vk)
        openers = [Opener() for _ in range(total_opener)]
        request = client.request_id(threshold_opener, openers)
        for _ in range(ITERATIONS):
            sigs_prime = client_request_id(request)
            time.sleep(5)
        print("Sig: RECEIVED")
        save_idp()

    # Aggregate the sigs
    sigs = [client.unbind_sig(sig_prime) for sig_prime in sigs_prime]
    client.agg_cred(sigs)
    assert client.verify_sig()

    proof = client.prove_id(b"Domain")
    del mem[:]
    for _ in range(ITERATIONS):
        send_proof(proof)
        time.sleep(5)
    print("Proof: VALIDATED")
    save_rp()

    # print(mem)
