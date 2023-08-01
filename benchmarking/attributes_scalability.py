import csv
import sys
from typing import List, Tuple

from timing_benchmark import timing_test

sys.path.append("../src")

import helper
from helper import BpGroupHelper
from client import Client
from idp import IdP, setup_idps
from rp import RP
from opener import Opener, check_sig, deanonymize, ban_users, ledger

time_unit = 1000  # For ms
attributes: List[Tuple[bytes, bool]] = []

threshold_idp = 3
total_idp = 4
threshold_opener = 2
total_opener = 3

num_iterations = 10


def run_timing_test(writer, type):
    for i in range(num_iterations):
        request_id_time, provide_id_time, unblind_time, aggr_sig_time, prove_id_time, verify_id_time, \
            deanonymize_time = timing_test()
        final_result = (
                request_id_time +
                provide_id_time +
                unblind_time +
                aggr_sig_time +
                prove_id_time +
                verify_id_time +
                deanonymize_time
        )
        writer.writerow({"type": type,
                         "num_attributes": len(attributes),
                         "time": final_result})


def attribute_scalling_test():
    with open("attributes_scalability.csv", mode="w", newline="") as file:
        fieldnames = ["type", "num_attributes", "time"]
        writer = csv.DictWriter(file, fieldnames)
        writer.writeheader()
        # Tests for the public attributes scaling
        global attributes
        type = "public"
        while len(attributes) != 18:
            attributes.append((b"public" + str(len(attributes)).encode(), False))
            attributes.append((b"public" + str(len(attributes) + 1).encode(), False))
            attributes = helper.sort_attributes(attributes)

            run_timing_test(writer, type)
            # Just adding two attributes that are different
            print(len(attributes), type)

        # Test for the private attribute scalability
        attributes.clear()  # Reset attributes
        type = "private"
        while len(attributes) != 18:
            attributes.append((b"private" + str(len(attributes)).encode(), True))
            attributes.append((b"private" + str(len(attributes) + 1).encode(), True))
            attributes = helper.sort_attributes(attributes)

            run_timing_test(writer, type)
            # Just adding two attributes that are different
            print(len(attributes), type)

        # Test for the mix attribute scalability
        attributes.clear()  # Reset attributes
        type = "mix"
        while len(attributes) != 18:
            attributes.append((b"public" + str(len(attributes)).encode(), False))
            attributes.append((b"private" + str(len(attributes) + 1).encode(), True))
            attributes = helper.sort_attributes(attributes)

            run_timing_test(writer, type)
            # Just adding two attributes that are different
            print(len(attributes), type)
        print("DONE")


if __name__ == "__main__":
    BpGroupHelper.setup(18)
    attribute_scalling_test()
