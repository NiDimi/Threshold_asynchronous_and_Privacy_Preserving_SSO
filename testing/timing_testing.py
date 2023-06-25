import sys
from typing import List, Tuple
import time

sys.path.append("../src")

from helper import BpGroupHelper
from client import Client
from idp import IdP
from rp import RP

BpGroupHelper.setup()
attributes: List[Tuple[bytes, bool]] = [
    (b"hidden1", True),
    (b"hidden2", True),
    (b"public1", False)]
time_unit = 1000
digits = 3

# ------------------ Idp - Client  ------------------
idp = IdP(len(attributes))
start_time = time.time()
pk = idp.keygen()
end_time = time.time()
elapsed_time_ms = (end_time - start_time) * time_unit
print(f"IdP - Keygen(): {elapsed_time_ms:.{digits}f} ms")

client = Client(pk)
start_time = time.time()
request = client.request_id(attributes, b"Data")
end_time = time.time()
elapsed_time_ms = (end_time - start_time) * time_unit
print(f"Client - request_id(): {elapsed_time_ms:.{digits}f} ms")

start_time = time.time()
sig_prime = idp.provide_id(request, b"Data")
end_time = time.time()
elapsed_time_ms = (end_time - start_time) * time_unit
print(f"IdP - provide_id(): {elapsed_time_ms:.{digits}f} ms")

assert sig_prime != 0
start_time = time.time()
sig = client.unbind_sig(sig_prime)
end_time = time.time()
elapsed_time_ms = (end_time - start_time) * time_unit
print(f"Client - unblind_sig(): {elapsed_time_ms:.{digits}f} ms")

start_time = time.time()
assert client.verify_sig(sig, attributes)
end_time = time.time()
elapsed_time_ms = (end_time - start_time) * time_unit
print(f"Client - verify_sig(): {elapsed_time_ms:.{digits}f} ms")

# ------------------ RP - Client  ------------------
start_time = time.time()
proof = client.prove_id(sig, attributes, b"Data", b"Domain")
end_time = time.time()
elapsed_time_ms = (end_time - start_time) * time_unit
print(f"Client - prove_id(): {elapsed_time_ms:.{digits}f} ms")

rp = RP(pk)
start_time = time.time()
assert rp.verify_id(proof, b"Data", b"Domain")
end_time = time.time()
elapsed_time_ms = (end_time - start_time) * time_unit
print(f"RP - verify_id(): {elapsed_time_ms:.{digits}f} ms")
