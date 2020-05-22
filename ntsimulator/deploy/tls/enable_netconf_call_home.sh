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

sleep 20

netconf_call_home=`jq '.["netconf-call-home"]' /opt/dev/scripts/configuration.json`


if [ $netconf_call_home = "false" ] ; then
   echo "NETCONF Call Home is disabled, nothing to do..."
   exit 0
else
   echo "Enabling NETCONF Call Home in device..."
fi

controller_ip=`jq '.["controller-details"] ."controller-ip"' /opt/dev/scripts/configuration.json`
controller_username=`jq '.["controller-details"] ."controller-username"' /opt/dev/scripts/configuration.json`
controller_password=`jq '.["controller-details"] ."controller-password"' /opt/dev/scripts/configuration.json`
controller_port=`jq '.["controller-details"] ."controller-port"' /opt/dev/scripts/configuration.json`
netconf_call_home_port=`jq '.["controller-details"] ."netconf-call-home-port"' /opt/dev/scripts/configuration.json`

SSH_PUB_KEY_MELACON="$(cat /home/netconf/.ssh/melacon.server.key.pub | awk '{print $2}')"

payload='{
      "odl-netconf-callhome-server:device": [
        {
          "odl-netconf-callhome-server:unique-id": "'$HOSTNAME'",
          "odl-netconf-callhome-server:ssh-host-key": "'$SSH_PUB_KEY_MELACON'",
          "odl-netconf-callhome-server:credentials": {
            "odl-netconf-callhome-server:username": "netconf",
            "odl-netconf-callhome-server:passwords": [
              "netconf"
            ]
          }
        }
      ]
}'

odl_ip=`sed -e 's/^"//' -e 's/"$//' <<<"$controller_ip"`
odl_username=`sed -e 's/^"//' -e 's/"$//' <<<"$controller_username"`
odl_password=`sed -e 's/^"//' -e 's/"$//' <<<"$controller_password"`

echo "Payload: $payload"

curl -v -H 'Content-Type: application/json' -X PUT -u $odl_username:$odl_password \
-d "$payload" http://$odl_ip:$controller_port/restconf/config/odl-netconf-callhome-server:netconf-callhome-server/allowed-devices/device/$HOSTNAME

echo '<netconf-server xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-server">
        <call-home>
          <netconf-client>
            <name>test_ssh_ch_client</name>
            <ssh>
              <endpoints>
                <endpoint>
                  <name>test_ssh_ch_endpt</name>
                  <address>'$odl_ip'</address>
                  <port>'$netconf_call_home_port'</port>
                </endpoint>
              </endpoints>
              <host-keys>
                <host-key>
                  <name>melacon server key</name>
                  <public-key>melacon_server_key</public-key>
                </host-key>
              </host-keys>
            </ssh>
            <connection-type>
              <persistent/>
            </connection-type>
          </netconf-client>
        </call-home>
    </netconf-server>' > connections.xml

sysrepocfg --merge=connections.xml --format=xml ietf-netconf-server
rm connections.xml

echo 'Done'
exit 0