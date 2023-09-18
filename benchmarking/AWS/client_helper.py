import sys

from json import loads, dumps
import requests


sys.path.append("../../src")
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

"""
------------------------------------ Functions ---------------------------------------------------------
"""


def build_url(server: str, port: int, route: str) -> str:
    """
    Construct a URL
    """
    return f"http://{server}:{port}{route}"


def test_connection():
    """
    Test the connection to the server
    """
    for server in SERVER_ADDR:
        url = build_url(server, 80, ROUTE_SERVER_INFO)
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
        url = build_url(server, 80, ROUTE_IDP_SET)
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


async def send_request(client, addr, route, json):
    """
    Asynchronously send a POST request to a specified address and route with given JSON data.

    :param client: The client instance to send the request
    :param addr: The server address to which the request should be sent
    :param route: The specific route or endpoint at the server for this request
    :param json: The request to send in json form
    :return: A dictionary containing:
            - status: The status returned by the server
            - load: The load value returned by the server (if present)
            - elapsed: The total time (in seconds) taken for the request

    """
    url = build_url(addr, 80, route)
    response = await client.post(url, data=dumps(json))
    response_data = loads(response.text)
    elapsed = response.elapsed.total_seconds()
    return {"status": response_data.get("status"), "load": response_data.get("load"), "elapsed": elapsed}














