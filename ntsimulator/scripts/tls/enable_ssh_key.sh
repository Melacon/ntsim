#! /bin/bash

sleep 5

SSH_PUB_KEY="$(cat /home/netconf/.ssh/id_dsa.pub| awk '{print $2}')"

echo '<system xmlns="urn:ietf:params:xml:ns:yang:ietf-system"><authentication><user><name>netconf</name><authorized-key><name>ssh_key</name><algorithm>ssh-dss</algorithm>' >> load_auth_pubkey.xml
echo '<key-data>'"$SSH_PUB_KEY"'</key-data></authorized-key></user></authentication></system>' >> load_auth_pubkey.xml

sysrepocfg --merge=load_auth_pubkey.xml --format=xml ietf-system
rm load_auth_pubkey.xml

ssh-keyscan -p 830 127.0.0.1 >> ~/.ssh/known_hosts

echo 'Done'
exit 0