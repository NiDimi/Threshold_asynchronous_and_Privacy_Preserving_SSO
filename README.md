# Threshold, Asynchronous and privacy-preserving Single Sign On
As part of my dissertation for my master's degree in UCL I created a threshold asynchronous and privacy preserving SSO 
with accountability properties
# Abstract
The delicate balance between authentication and privacy preservation remains a significant concern in authentication systems. Open ID Connect is an example of this since it suffers from privacy issues despite being the dominant SSO solution used by more than a million websites. In particular, the identity providers can track the users, the relying parties can link each user's sign-on attempt, and it requires all entities to be online in order to work. Addressing these challenges, we introduce what we believe to be the first threshold asynchronous and privacy-preserving single sign-on, with the option to de-anonymize and ban misbehaving users. Our approach draws on the foundations set by El Passo, Coconut, and the group signatures suggested by Camenisch et al. to achieve distributed threshold issuance, multiple unlinkable selective attributes, prevent Sybil identities, tracking protection, and offer accountability for the user's actions, all in a 64 bytes credential. We evaluated our scheme, and we concluded that it scales reasonably well both in increasing the number of attributes and the number of thresholds in issuers. While our test indicated limited throughput, we stress that these outcomes may be the result of the testing environment. Finally, we suggested some Web3 applications and future directions for our scheme.

# Pre-requisites 
The code is built on top of [petlib](https://github.com/gdanezis/petlib) and [bplib](https://github.com/moonkace24/Corrected_bplib)



