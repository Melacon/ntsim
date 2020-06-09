#!/bin/bash
################################################################################
#
# Copyright 2019 highstreet technologies GmbH and others
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

echo "Loading data into sysrepo..."

result=$(netopeer2-cli <<-END
	knownhosts --del 0
    knownhosts --del 0
END
)

SSH_PUB_KEY_MELACON="$(cat /home/netconf/.ssh/melacon.server.key.pub)"

echo "Writing the public key to the known_hosts..."
echo "[127.0.0.1]:830 $SSH_PUB_KEY_MELACON" > /root/.ssh/known_hosts

pyang -f sample-xml-skeleton --sample-xml-list-entries 2 *.yang

result=$(netopeer2-cli <<-END
    auth keys add /home/netconf/.ssh/melacon.server.key.pub /home/netconf/.ssh/melacon.server.key
	connect --host 127.0.0.1 --login netconf
	user-rpc --content=/opt/dev/yang/edit_config_operation.xml
	disconnect
END
)

count=1

while [[ $count -le 100 ]] && [[ "$result" != "OK" ]]
do
  ((count++))
  pyang -f sample-xml-skeleton --sample-xml-list-entries 2 *.yang
  
  result=$(netopeer2-cli <<-END
	connect --host 127.0.0.1 --login netconf
	user-rpc --content=edit_config_operation.xml
	disconnect
END
)
done

echo "Finished loading data into sysrepo. Removing edit-config XML..."
rm -f /opt/dev/yang/edit_config_operation.xml

echo "Done..."
exit 0
