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

int_re='^[0-9]+$'

ssh_conn=`jq '.["ssh-connections"]' /opt/dev/scripts/configuration.json`
tls_conn=`jq '.["tls-connections"]' /opt/dev/scripts/configuration.json`

echo "Enabling $ssh_conn SSH connections and $tls_conn TLS connections in device..."

# if [ "$#" -ne 2 ]; then
#   echo "Usage: $0 NUM_SSH_CONNECTIONS NUM_TLS_CONNECTIONS" >&2
#   exit 1
# fi

if ! [[ $ssh_conn =~ $int_re ]] ; then
   echo "error: Argument '$ssh_conn' is not a number" >&2
   exit 1
fi

if ! [[ $tls_conn =~ $int_re ]] ; then
   echo "error: Argument '$tls_conn' is not a number" >&2
   exit 1
fi

netconf_port=830

if [ $IPv6Enabled = "true" ]; then
    localhost_address="::"
else
    localhost_address="0.0.0.0"
fi

echo '<netconf-server xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-server"><listen>' > connections.xml

for (( ssh_counter=0; ssh_counter<$ssh_conn; ssh_counter++ ))
do
  echo "<endpoint><name>MNG$ssh_counter</name><ssh><address>$localhost_address</address><port>$netconf_port</port><host-keys><host-key><name>imported SSH key</name><public-key>ssh_host_rsa_key</public-key></host-key><host-key><name>Melacon Server key</name><public-key>melacon_server_key</public-key></host-key></host-keys></ssh></endpoint>" >> connections.xml
  ((netconf_port++))
done

for (( tls_counter=0; tls_counter<$tls_conn; tls_counter++ ))
do
  echo "<endpoint><name>MNGTLS$tls_counter</name><tls><address>$localhost_address</address><port>$netconf_port</port><certificates><certificate><name>melacon_server_cert</name></certificate></certificates><client-auth><trusted-ca-certs>trusted_ca_list</trusted-ca-certs><cert-maps><cert-to-name><id>1</id><fingerprint>02:E9:38:1F:F6:8B:62:DE:0A:0B:C5:03:81:A8:03:49:A0:00:7F:8B:F3</fingerprint><map-type xmlns:x509c2n=\"urn:ietf:params:xml:ns:yang:ietf-x509-cert-to-name\">x509c2n:specified</map-type><name>netconf</name></cert-to-name></cert-maps></client-auth></tls></endpoint>" >> connections.xml
  ((netconf_port++))
done

echo '</listen></netconf-server>' >> connections.xml

sysrepocfg --import=connections.xml --format=xml ietf-netconf-server
rm connections.xml

echo 'Done'
exit 0