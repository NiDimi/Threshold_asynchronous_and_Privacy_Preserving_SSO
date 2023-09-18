import asyncio
import csv
from typing import List, Tuple

import httpx

from client_helper import *

sys.path.append("../../src")
import helper
from helper import BpGroupHelper, pack, unpack
from client import Client
from idp import IdP, setup_idps
from rp import RP
from opener import Opener, check_sig, deanonymize

ITERATIONS = 100

"""
------------------------------------ Functions ---------------------------------------------------------
"""


def get_t_number(numbers):
    sorted_numbers = sorted(numbers)
    return sorted_numbers[threshold_idp - 1]


async def async_request_id(request):
    """
    Asynchronously send a request for credentials in all the IdPS
    :param request: The request to send
    :return: The signatures returned and the smaller t time it took to return all
    """
    json = {"request": request.to_json()}
    async with httpx.AsyncClient() as client:
        tasks = [send_request(client, addr, ROUTE_IDP_PROVIDEID, json) for addr in SERVER_ADDR]
        results = await asyncio.gather(*tasks)
    sigs = []
    numbers = []
    for r in results:
        assert r["status"] == "OK"
        sig = unpack(r["load"])
        sigs.append(sig)
        numbers.append(r["elapsed"])
    elapsed_time = get_t_number(numbers)
    return sigs, elapsed_time


async def measure_threshold_latency():
    """
    Asynchronous function that keeps sending requests to the IdPs with different thresholds.
    Saves the results in a .csv file
    """
    client = Client(attributes, aggr_vk)
    openers = [Opener() for _ in range(total_opener)]
    request = client.request_id(threshold_opener, openers)
    with open('../data/latency.csv', 'w', newline='') as file:
        fieldnames = ["Threshold", "Time"]
        writer = csv.DictWriter(file, fieldnames)
        writer.writeheader()
        for i in range(1, len(SERVER_ADDR) + 1):
            threshold_idp = i
            print("Starting with IdPs:", threshold_idp)
            for _ in range(ITERATIONS):
                sigs_prime, elapsed_time = await async_request_id(request)
                sigs = [client.unbind_sig(sig_prime) for sig_prime in sigs_prime]
                client.agg_cred(sigs)
                assert client.verify_sig()
                writer.writerow({fieldnames[0]: threshold_idp, fieldnames[1]: elapsed_time * 1000}, )


"""
------------------------------------ start of the program ---------------------------------------------------------
"""
if __name__ == "__main__":
    attributes: List[Tuple[bytes, bool]] = [
        (b"hidden1", True),
        (b"hidden2", True),
        (b"hidden3", True),
        (b"public1", False)]
    test_connection()
    print("Test connection: OKAY")
    BpGroupHelper.setup(len(attributes))
    total_opener = 3
    threshold_opener = 2
    total_idp = 2
    threshold_idp = 1

    idps = setup_idps(threshold_idp, total_idp)
    print("Keys set: OKAY")
    vk = [idp.vk for idp in idps]
    aggr_vk = helper.agg_key(vk)
    set_idp_keys(idps, aggr_vk)  # Send to each IdP server the key generated when emulating the ss

    asyncio.run(measure_threshold_latency())
    print("Test concluded")

