import asyncio
import csv
import time
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

MAX_REQUESTS = 10

"""
------------------------------------ Functions ---------------------------------------------------------
"""


async def async_request_id(request):
    """
    Asynchronously send a request for credentials in all the IdPS
    :param request: The request to send
    """
    json = {"request": request.to_json()}
    async with httpx.AsyncClient() as client:
        tasks = [send_request(client, SERVER_ADDR[0], ROUTE_IDP_PROVIDEID, json)]
        results = await asyncio.gather(*tasks)
    for r in results:
        assert r["status"] == "OK"


async def async_send_parallel_requests(number_of_requests, request):
    """
    Just a wrapper function that genertes the total number of requests we need
    :param number_of_requests: The number of requests to send
    :param request: The request
    """
    tasks = [async_request_id(request) for _ in range(number_of_requests)]
    await asyncio.gather(*tasks)


async def measure_throughput_latency():
    """
    Keep increasing the number of requests and measure how long an IdP takes to respond to them
    """
    client = Client(attributes, aggr_vk)
    openers = [Opener() for _ in range(total_opener)]
    request = client.request_id(threshold_opener, openers)
    with open('../data/throughput.csv', 'w', newline='') as file:
        fieldnames = ["Number_of_Requests", "Time"]
        writer = csv.DictWriter(file, fieldnames)
        writer.writeheader()
        for n in range(1, MAX_REQUESTS+1):
            time.sleep(1)
            print(f"Sending {n} parallel requests...")
            start_time = time.perf_counter()
            await async_send_parallel_requests(n, request)
            elapsed_time = time.perf_counter() - start_time
            print(elapsed_time)
            writer.writerow({fieldnames[0]: n, fieldnames[1]: elapsed_time}, )


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

    asyncio.run(measure_throughput_latency())
    print("Test concluded")
