# Threshold, Asynchronous and privacy-preserving Single Sign On
As part of my dissertation for my master's degree in UCL I created a threshold asynchronous and privacy preserving SSO 
with accountability properties
# Abstract
The delicate balance between authentication and privacy preservation remains a significant concern in authentication systems. Open ID Connect is an example of this since it suffers from privacy issues despite being the dominant SSO solution used by more than a million websites. In particular, the identity providers can track the users, the relying parties can link each user's sign-on attempt, and it requires all entities to be online in order to work. Addressing these challenges, we introduce what we believe to be the first threshold asynchronous and privacy-preserving single sign-on, with the option to de-anonymize and ban misbehaving users. Our approach draws on the foundations set by El Passo, Coconut, and the group signatures suggested by Camenisch et al. to achieve distributed threshold issuance, multiple unlinkable selective attributes, prevent Sybil identities, tracking protection, and offer accountability for the user's actions, all in a 64 bytes credential. We evaluated our scheme, and we concluded that it scales reasonably well both in increasing the number of attributes and the number of thresholds in issuers. While our test indicated limited throughput, we stress that these outcomes may be the result of the testing environment. Finally, we suggested some Web3 applications and future directions for our scheme.

# Pre-requisites 
The code is built on top of [petlib](https://github.com/gdanezis/petlib) and [bplib](https://github.com/moonkace24/Corrected_bplib)


# A Normal Run Through the Code

## Setup parameters 

```python
threshold_idp = 2
total_idp = 5
threshold_opener = 2
total_opener = 3
attributes: List[Tuple[bytes, bool]] = [
    (b"hidden1", True),
    (b"hidden2", True),
    (b"public1", False),
    (b"hidden3", True)]
BpGroupHelper.setup(len(attributes))
attributes = helper.sort_attributes(attributes)

```

## Setup the entities of the protocol
```python
idps = setup_idps(threshold_idp, total_idp)
openers = [Opener() for _ in range(total_opener)]
rp = RP(b"Domain")
# We need to create the aggregated public key in order to create the client
vk = [idp.vk for idp in idps]
# Remove one of the key for testing, we need just the threshold not all
vk[0] = None
aggr_vk = helper.agg_key(vk)
client = Client(attributes, aggr_vk)
```

## Generate a valid credential
```python
# Communication with Client - IdP
request = client.request_id(threshold_opener, openers)
sigs_prime = [idp.provide_id(request, aggr_vk) for idp in idps]
sigs = [client.unbind_sig(sig_prime) for sig_prime in sigs_prime]
# Hide some sigs so we can test the threshold setting
sigs[1] = sigs[4] = None
# Creaate the aggregated signature which would be stored in the client
client.agg_cred(sigs)
```

## Prove credential to RP
```python
proof = client.prove_id(rp.domain)
assert rp.verify_id(proof, aggr_vk)
```

## De-anonymise User
```python
assert deanonymize(openers, proof, aggr_vk) == request.user_id

# If the user tries to prove the credentials now it should fail
assert not rp.verify_id(proof, aggr_vk)
```


# To Run The Tests

```
$ cd testing
$ pytest -v
```