import sys
from json import dumps, loads

from flask import Flask, request

from idp_wrapper import IdPWrapper

sys.path.append("../src")

from helper import BpGroupHelper, pack, unpack
from rp import RP
from request import Request
from credproof import CredProof

"""
Code strongly inspired by https://github.com/asonnino/coconut-timing
"""

# Static fields
idp = None
aggr_vk = None
rp = RP(b"Domain")

# Start the lib
BpGroupHelper.setup(4)


# make packet for client
def format(load):
    return dumps({
        "status": "OK",
        "load": load,
    })


"""
------------------------------------ Wrappers for the functionality --------------------------------------------------
"""


def set_keys_wrapper(data):
    """ Just sets the keys"""
    global idp
    idp = IdPWrapper().getIdP(unpack(data["sk"]), unpack(data["vk"]))
    global aggr_vk
    aggr_vk = unpack(data["aggr_vk"])


def provide_id_wrapper(data):
    """Return the sig"""
    id_request = Request.from_json(data["request"])
    sig_prime = idp.provide_id(id_request, aggr_vk)
    return format(pack(sig_prime))


def verify_id_wrapper(data):
    id_proof = CredProof.from_json(data["proof"])
    return rp.verify_id(id_proof, aggr_vk)


"""
------------------------------------ Web App ---------------------------------------------------------
"""
app = Flask(__name__)
app.secret_key = None


# /
# Return just ok to make sure the server is running fine
@app.route("/", methods=["Get", "Post"])
def test():
    return dumps({"status": "OK"})


# /idp/set
# Sets the sk and vk of this idp server. Also the aggr_vk
@app.route("/idp/set", methods=["Get", "Post"])
def set_idp_keys():
    if request.method == "POST":
        try:
            data = loads(request.data.decode("utf-8"))
            set_keys_wrapper(data)
            return dumps({"status": "OK"})
        except KeyError as e:
            return dumps({"status": "Key ERROR", "message": e.args})
        except Exception as e:
            return dumps({"status": "ERROR", "message": e.args})
    else:
        return dumps({"status": "ERROR", "message": "Use POST method."})


# /idp/provideid
# Return an id (signature) to the client that requested it
@app.route("/idp/provideid", methods=["Get", "Post"])
def idp_provide_id():
    if request.method == "POST":
        try:
            data = loads(request.data.decode("utf-8"))
            return provide_id_wrapper(data)
        except KeyError as e:
            return dumps({"status": "Key ERROR", "message": e.args})
        except Exception as e:
            return dumps({"status": "ERROR", "message": e.args})
    else:
        return dumps({"status": "ERROR", "message": "Use POST method."})


# /rp/verifyid
# Verifies that the id of the user is valid
@app.route("/rp/verifyid", methods=["Get", "Post"])
def rp_verify_id():
    if request.method == "POST":
        try:
            data = loads(request.data.decode("utf-8"))
            if verify_id_wrapper(data):
                return dumps({"status": "OK"})
            return dumps({"Status": "Verification Failed"})
        except KeyError as e:
            return dumps({"status": "Key ERROR", "message": e.args})
        except Exception as e:
            return dumps({"status": "ERROR", "message": e.args})
    else:
        return dumps({"status": "ERROR", "message": "Use POST method."})


"""
------------------------------------ start of the program ---------------------------------------------------------
"""
if __name__ == "__main__":
    port = int(sys.argv[1])
    app.run("0.0.0.0", port)
