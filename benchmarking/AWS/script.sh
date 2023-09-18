#!/bin/bash

# Script that sets up the server in the AWS instance
sudo apt update; sudo apt -y upgrade;
sudo apt -y install git;
git clone https://github.com/moonkace24/Asynchronous_and_Privacy_Preserving_SSO.git;
sudo apt -y install python3.10-dev libssl-dev libffi-dev;
sudo apt -y install python3-pip;
sudo pip3 install petlib;
git clone https://github.com/moonkace24/Corrected_bplib.git;
sudo python3 Corrected_bplib/setup.py install;
sudo pip3 install numpy; sudo pip3 install flask;
