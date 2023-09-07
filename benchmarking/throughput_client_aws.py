import asyncio
import csv
import sys
import time
from typing import List, Tuple
import httpx

from binascii import hexlify
from json import loads, dumps

import grequests
import requests
from engineio.async_drivers import aiohttp
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
# SERVER_ADDR = [
#     "ec2-13-41-165-172.eu-west-2.compute.amazonaws.com",
# ]
SERVER_ADDR = [
    "127.0.0.1",
]

ROUTE_SERVER_INFO = "/"
ROUTE_IDP_SET = "/idp/set"
ROUTE_IDP_PROVIDEID = "/idp/provideid"
ROUT_RP_VERIFYID = "/rp/verifyid"

# timings
mem = []

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


async def async_client_request_id(request):
    """
    Send an asynchronous request to the IdP servers for a sig

    :return: the list of the sigs from the IdP
    """
    json = {"request": request.to_json()}

    async with httpx.AsyncClient() as client:
        tasks = [client.post(f"http://{addr}:80{ROUTE_IDP_PROVIDEID}", json=json) for addr in SERVER_ADDR]
        responses = await asyncio.gather(*tasks)

        sigs = []
        for response in responses:
            r = response.json()
            assert r["status"] == "OK"
            sig = unpack(r["load"])
            sigs.append(sig)
        return sig


async def send_parallel_requests(n: int, request):
    """
    Send 'n' parallel requests to the server
    """
    tasks = [async_client_request_id(request) for _ in range(n)]
    await asyncio.gather(*tasks)


def measure_throughput_incremental():
    with open('throughput_idp.csv', 'w', newline='') as csvfile:

        csvwriter = csv.writer(csvfile)
        # Writing headers to the CSV
        csvwriter.writerow(['Number_of_Requests', 'Elapsed_Time'])

        for n in range(1, 50):  # From 1 to 250
            time.sleep(5)
            print(f"Sending {n} parallel requests...")
            start_time = time.time()
            asyncio.run(send_parallel_requests(n, request))
            elapsed_time = time.time() - start_time
            print(f"Took {elapsed_time:.4f} seconds for {n} requests")

            # Writing the number of requests and elapsed time to the CSV
            csvwriter.writerow([n, elapsed_time])


def client_request_id(request):
    """
    Send a request to the IdP servers for a sig

    :return: the list of the sigs from the IdP
    """
    json = {"request": request.to_json()}
    sigs = []
    return async_request(ROUTE_IDP_PROVIDEID, json)


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

    return sigs


async def async_send_proof(proof):
    """
    Asynchronously sends proof of posession of credentials to the RP

    :param proof: The proof of the client
    """
    json = {"proof": proof.to_json()}

    async with httpx.AsyncClient() as client:
        response = await client.post(f"http://{SERVER_ADDR[0]}:80{ROUT_RP_VERIFYID}", json=json)

        r = response.json()
        assert r["status"] == "OK"
        mem.append({'time': response.elapsed.total_seconds()})
    return True


async def send_parallel_proofs(n: int, proof):
    """
    Send 'n' parallel proofs to the server
    """
    tasks = [async_send_proof(proof) for _ in range(n)]
    await asyncio.gather(*tasks)


def measure_throughput_proofs_incremental(proof):
    with open('throughput_rp.csv', 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)

        # Writing headers to the CSV
        csvwriter.writerow(['Number_of_Proofs', 'Elapsed_Time'])

        for n in range(1, 50):  # From 1 to 250
            time.sleep(5)
            print(f"Sending {n} parallel proofs...")
            start_time = time.time()
            asyncio.run(send_parallel_proofs(n, proof))
            elapsed_time = time.time() - start_time
            print(f"Took {elapsed_time:.4f} seconds for {n} proofs")

            # Writing the number of proofs and elapsed time to the CSV
            csvwriter.writerow([n, elapsed_time])


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
    total_idp = 2
    threshold_idp = 1

    idps = setup_idps(threshold_idp, total_idp)
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

    measure_throughput_incremental()
    # sigs_prime = client_request_id(request)
    print("Sig: RECEIVED")

    # # Aggregate the sigs
    # sigs = [client.unbind_sig(sig_prime) for sig_prime in sigs_prime]
    # client.agg_cred(sigs)
    # assert client.verify_sig()
    #
    # proof = client.prove_id(b"Domain")
    # del mem[:]
    # measure_throughput_proofs_incremental(proof)
    # print("Proof: VALIDATED")
