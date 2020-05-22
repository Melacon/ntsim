#! /bin/bash
################################################################################
#
# Copyright 2020 highstreet technologies GmbH and others
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

################################################################################
# Script to enable SSH publicKey authentication in the localhost NETCONF server

sleep 5

SSH_PUB_KEY="$(cat /home/netconf/.ssh/id_dsa.pub| awk '{print $2}')"

echo '<system xmlns="urn:ietf:params:xml:ns:yang:ietf-system"><authentication><user><name>netconf</name><authorized-key><name>ssh_key</name><algorithm>ssh-dss</algorithm>' >> load_auth_pubkey.xml
echo '<key-data>'"$SSH_PUB_KEY"'</key-data></authorized-key></user></authentication></system>' >> load_auth_pubkey.xml

sysrepocfg --merge=load_auth_pubkey.xml --format=xml ietf-system
rm load_auth_pubkey.xml

ssh-keyscan -p 830 127.0.0.1 >> ~/.ssh/known_hosts

echo "Generating the new ssh key..."
openssl genrsa -out melacon.server.key 2048

openssl req -new -sha256 -key melacon.server.key -subj "/C=US/ST=CA/O=MeLaCon, Inc./CN=melacon.com" -out melacon.server.csr
openssl x509 -req -in melacon.server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out melacon.server.crt -days 500 -sha256
rm melacon.server.csr

MELACON_SERVER_KEY="$(sed '1d;$d' melacon.server.key)"

echo '<action xmlns="urn:ietf:params:xml:ns:yang:1"><keystore xmlns="urn:ietf:params:xml:ns:yang:ietf-keystore"><private-keys><load-private-key><name>melacon_server_key</name>' >> load_private_key.xml
echo '<private-key>'"$MELACON_SERVER_KEY"'</private-key></load-private-key></private-keys></keystore></action>' >> load_private_key.xml

netopeer2-cli <<END
auth pref publickey 1000
auth keys add /home/netconf/.ssh/id_dsa.pub /home/netconf/.ssh/id_dsa
connect --host 127.0.0.1 --login netconf
user-rpc --content=load_private_key.xml
disconnect
END

rm load_private_key.xml

MELACON_CERT="$(sed '1d;$d' melacon.server.crt)"
CA_CERT="$(sed '1d;$d' ca.pem)"

echo '<keystore xmlns="urn:ietf:params:xml:ns:yang:ietf-keystore"><private-keys><private-key><name>melacon_server_key</name><certificate-chains><certificate-chain><name>melacon_server_cert</name>' >> load_server_certs.xml
echo '<certificate>'"$MELACON_CERT"'</certificate></certificate-chain></certificate-chains></private-key></private-keys><trusted-certificates><name>trusted_ca_list</name><trusted-certificate><name>ca</name>' >> load_server_certs.xml
echo '<certificate>'"$CA_CERT"'</certificate></trusted-certificate></trusted-certificates></keystore>' >> load_server_certs.xml

sysrepocfg --merge=load_server_certs.xml --format=xml ietf-keystore
rm load_server_certs.xml

echo 'Done'
exit 0