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

TIME_UNIT = 1000
ATTRIBUTES: List[Tuple[bytes, bool]] = [
    (b"hidden1", True),
    (b"hidden2", True),
    (b"public1", False),
]
ITERATIONS = 30


def timing_test(idps, client, rp, openers, aggr_vk, to):
    # time.sleep(2.5)
    # Request ID
    start_time = time.time()
    request = client.request_id(to, openers)
    end_time = time.time()
    request_id_time = (end_time - start_time) * TIME_UNIT
    # Provide ID
    start_time = time.time()
    sigs_prime = [idp.provide_id(request, aggr_vk) for idp in idps]
    end_time = time.time()
    provide_id_time = (end_time - start_time) * TIME_UNIT
    # Unblind
    start_time = time.time()
    sigs = [client.unbind_sig(sig_prime) for sig_prime in sigs_prime]
    end_time = time.time()
    unblind_time = (end_time - start_time) * TIME_UNIT
    # Aggregate sigs
    start_time = time.time()
    client.agg_cred(sigs)
    end_time = time.time()
    aggr_sig_time = (end_time - start_time) * TIME_UNIT
    assert client.verify_sig()  # Just verify the correct result
    # Prove ID
    start_time = time.time()
    proof = client.prove_id(rp.domain)
    end_time = time.time()
    prove_id_time = (end_time - start_time) * TIME_UNIT
    # Verify ID
    start_time = time.time()
    temp = rp.verify_id(proof, aggr_vk)
    end_time = time.time()
    verify_id_time = (end_time - start_time) * TIME_UNIT
    assert temp  # Just check everything went okay
    # Ban user
    start_time = time.time()
    id = deanonymize(openers, proof, aggr_vk)
    end_time = time.time()
    deanonymize_time = (end_time - start_time) * TIME_UNIT
    assert id == request.user_id
    # Remove the add users because it is going to grow exponential otherwise both ledger and ban_users
    ban_users.pop(id)
    ledger.pop(request.user_id)
    return request_id_time, provide_id_time, unblind_time, aggr_sig_time, prove_id_time, verify_id_time, deanonymize_time


def setup(q, ti, ni, to, no):
    # Setup
    BpGroupHelper.setup(q)
    idps = setup_idps(ti, ni)
    # Generate the entities in the protocol
    openers = [Opener() for _ in range(no)]
    vk = [idp.vk for idp in idps]
    aggr_vk = helper.agg_key(vk)
    client = Client(ATTRIBUTES, aggr_vk)
    rp = RP(b"Domain")
    return idps, client, rp, openers, aggr_vk


def start_test(q, ti, ni, to, no):
    idps, client, rp, openers, aggr_vk = setup(q, ti, ni, to, no)
    # just add 10 banned random users and 10 existing users in the ledger
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

        for i in range(ITERATIONS):
            request_id_time, provide_id_time, unblind_time, aggr_sig_time, prove_id_time, verify_id_time, \
                deanonymize_time = timing_test(idps, client, rp, openers, aggr_vk, threshold_opener)
            # if deanonymize_time > 200 or provide_id_time > 100:
            #     continue
            writer.writerow({'request_id': request_id_time,
                             'provide_id': provide_id_time,
                             'unblind': unblind_time,
                             'aggr_sig': aggr_sig_time,
                             'prove_id': prove_id_time,
                             'verify_id': verify_id_time,
                             'deanonymize': deanonymize_time})
            print(i)


if __name__ == "__main__":
    threshold_idp = 3
    total_idp = 4
    threshold_opener = 2
    total_opener = 3
    start_test(3, threshold_idp, total_idp, threshold_opener, total_opener)
    print("DONE")
