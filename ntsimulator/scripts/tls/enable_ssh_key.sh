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

echo 'Done'
exit 0