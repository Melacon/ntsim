#!/bin/bash

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
