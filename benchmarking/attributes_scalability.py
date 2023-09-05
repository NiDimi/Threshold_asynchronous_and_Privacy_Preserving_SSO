import csv
import sys
from typing import List, Tuple

from timing_benchmark import timing_test, setup

sys.path.append("../src")

import helper
from helper import BpGroupHelper
from client import Client
from idp import IdP, setup_idps
from rp import RP
from opener import Opener, check_sig, deanonymize, ban_users, ledger

TIME_UNIT = 1000  # For ms
ATTRIBUTES: List[Tuple[bytes, bool]] = [(b"private", True)]  # We always have to have one private

ITERATIONS = 100
MAX_ATTRIBUTES = 19


def run_timing_test(writer, type, idps, client, rp, openers, aggr_vk, to):
    for i in range(ITERATIONS):
        request_id_time, provide_id_time, unblind_time, aggr_sig_time, prove_id_time, verify_id_time, \
            deanonymize_time = timing_test(idps, client, rp, openers, aggr_vk, to)
        final_result = (
                request_id_time +
                provide_id_time +
                unblind_time +
                aggr_sig_time +
                prove_id_time +
                verify_id_time
        )
        writer.writerow({"type": type,
                         "num_attributes": len(ATTRIBUTES),
                         "time": final_result})


def attribute_scalling_test(idps, client, rp, openers, aggr_vk, to):
    with open("attributes_scalability.csv", mode="w", newline="") as file:
        fieldnames = ["type", "num_attributes", "time"]
        writer = csv.DictWriter(file, fieldnames)
        writer.writeheader()
        # Tests for the public attributes scaling
        global ATTRIBUTES
        type = "public"
        while len(ATTRIBUTES) < MAX_ATTRIBUTES:
            ATTRIBUTES.append((b"public" + str(len(ATTRIBUTES)).encode(), False))
            ATTRIBUTES.append((b"public" + str(len(ATTRIBUTES) + 1).encode(), False))

            ATTRIBUTES = helper.sort_attributes(ATTRIBUTES)
            client.set_attributes(ATTRIBUTES)

            run_timing_test(writer, type, idps, client, rp, openers, aggr_vk, to)
            # Just adding two attributes that are different
            print(len(ATTRIBUTES), type)

        # Test for the private attribute scalability
        ATTRIBUTES.clear()  # Reset attributes
        ATTRIBUTES.append((b"private", True))
        type = "private"
        while len(ATTRIBUTES) < MAX_ATTRIBUTES:
            ATTRIBUTES.append((b"private" + str(len(ATTRIBUTES)).encode(), True))
            ATTRIBUTES.append((b"private" + str(len(ATTRIBUTES) + 1).encode(), True))

            ATTRIBUTES = helper.sort_attributes(ATTRIBUTES)
            client.set_attributes(ATTRIBUTES)

            run_timing_test(writer, type, idps, client, rp, openers, aggr_vk, to)
            # Just adding two attributes that are different
            print(len(ATTRIBUTES), type)

        # Test for the mix attribute scalability
        ATTRIBUTES.clear()  # Reset attributes
        ATTRIBUTES.append((b"private", True))
        type = "mix"
        while len(ATTRIBUTES) < MAX_ATTRIBUTES:
            ATTRIBUTES.append((b"public" + str(len(ATTRIBUTES)).encode(), False))
            ATTRIBUTES.append((b"private" + str(len(ATTRIBUTES) + 1).encode(), True))

            ATTRIBUTES = helper.sort_attributes(ATTRIBUTES)
            client.set_attributes(ATTRIBUTES)

            run_timing_test(writer, type, idps, client, rp, openers, aggr_vk, to)
            # Just adding two attributes that are different
            print(len(ATTRIBUTES), type)


def start_test(q, ti, ni, to, no):
    idps, client, rp, openers, aggr_vk = setup(q, ti, ni, to, no)
    attribute_scalling_test(idps, client, rp, openers, aggr_vk, to)


if __name__ == "__main__":
    threshold_idp = 3
    total_idp = 4
    threshold_opener = 2
    total_opener = 3
    start_test(MAX_ATTRIBUTES, threshold_idp, total_idp, threshold_opener, total_opener)
    print("DONE")
