import time
import csv
import sys
from typing import List, Tuple

sys.path.append("../src")

import helper
from helper import BpGroupHelper
from client import Client
from idp import IdP, setup_idps
from rp import RP
from opener import Opener, check_sig, deanonymize, ban_users, ledger

"""
Write the test an number of times and hold the time 
Parameters ti=3, ni=4, to=2, no=3, attributes=3, ban users = 10

"""
time_unit = 1000  # For ms
attributes: List[Tuple[bytes, bool]] = [
    (b"hidden1", True),
    (b"hidden2", True),
    (b"public1", False), ]
attributes = helper.sort_attributes(attributes)

threshold_idp = 3
total_idp = 4
threshold_opener = 2
total_opener = 3

num_iterations = 3000


def timing_test():
    idps = setup_idps(threshold_idp, total_idp)
    # Generate the entities in the protocol
    openers = [Opener() for _ in range(total_opener)]
    vk = [idp.vk for idp in idps]
    aggr_vk = helper.agg_key(vk)
    client = Client(attributes, aggr_vk)
    rp = RP(b"Domain")
    # Request ID
    start_time = time.time()
    request = client.request_id(threshold_opener, openers)
    end_time = time.time()
    request_id_time = (end_time - start_time) * time_unit
    # Provide ID
    start_time = time.time()
    sigs_prime = [idp.provide_id(request, aggr_vk) for idp in idps]
    end_time = time.time()
    provide_id_time = (end_time - start_time) * time_unit
    # Unblind
    start_time = time.time()
    sigs = [client.unbind_sig(sig_prime) for sig_prime in sigs_prime]
    end_time = time.time()
    unblind_time = (end_time - start_time) * time_unit
    # Aggregate sigs
    start_time = time.time()
    client.agg_cred(sigs)
    end_time = time.time()
    aggr_sig_time = (end_time - start_time) * time_unit
    assert client.verify_sig()  # Just verify the correct result
    # Prove ID
    start_time = time.time()
    proof = client.prove_id(rp.domain)
    end_time = time.time()
    prove_id_time = (end_time - start_time) * time_unit
    # Verify ID
    start_time = time.time()
    temp = rp.verify_id(proof, aggr_vk)
    end_time = time.time()
    verify_id_time = (end_time - start_time) * time_unit
    assert temp  # Just check everything went okay
    # Ban user
    start_time = time.time()
    id = deanonymize(openers, proof, aggr_vk)
    end_time = time.time()
    deanonymize_time = (end_time - start_time) * time_unit
    assert id == request.user_id
    # Remove the add users because it is going to grow exponential otherwise both ledger and ban_users
    ban_users.pop(id)
    ledger.pop(request.user_id)
    return request_id_time, provide_id_time, unblind_time, aggr_sig_time, prove_id_time, verify_id_time, deanonymize_time


if __name__ == "__main__":
    # just add 10 banned random users and 10 existing users in the ledger
    BpGroupHelper.setup(3)
    o, g2 = BpGroupHelper.o, BpGroupHelper.g2
    for i in range(10):
        r = o.random()
        ban_users[r] = r * g2
        ledger[r] = {1: (r * g2, r * g2, (r * g2)), 2: (r * g2, r * g2, (r * g2))}
    # Open file
    with open("timing_benchmark.csv", mode="w", newline="") as file:
        fieldnames = ['request_id', 'provide_id', 'unblind', 'aggr_sig', 'prove_id', 'verify_id', 'deanonymize']
        writer = csv.DictWriter(file, fieldnames)
        writer.writeheader()

        for i in range(num_iterations):
            request_id_time, provide_id_time, unblind_time, aggr_sig_time, prove_id_time, verify_id_time, \
                deanonymize_time = timing_test()
            writer.writerow({'request_id': request_id_time,
                             'provide_id': provide_id_time,
                             'unblind': unblind_time,
                             'aggr_sig': aggr_sig_time,
                             'prove_id': prove_id_time,
                             'verify_id': verify_id_time,
                             'deanonymize': deanonymize_time})
            print(i)
    print("DONE")
