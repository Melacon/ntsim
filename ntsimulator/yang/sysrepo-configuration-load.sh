#!/bin/bash

sleep 20

echo "Loading data into sysrepo..."

#SSH_PUB_KEY="$(cat /home/netconf/.ssh/id_dsa.pub| awk '{print $2}')"

#echo '<system xmlns="urn:ietf:params:xml:ns:yang:ietf-system"><authentication><user><name>netconf</name><authorized-key><name>ssh_key</name><algorithm>ssh-dss</algorithm>' >> load_auth_pubkey.xml
#echo '<key-data>'"$SSH_PUB_KEY"'</key-data></authorized-key></user></authentication></system>' >> load_auth_pubkey.xml

#sysrepocfg --merge=load_auth_pubkey.xml --format=xml ietf-system
#rm load_auth_pubkey.xml
#
#ssh-keyscan -p 830 localhost >> ~/.ssh/known_hosts

pyang -f sample-xml-skeleton --sample-xml-list-entries 3 *.yang

result=$(netopeer2-cli <<-END
	connect --login netconf
	user-rpc --content=/opt/dev/yang/edit_config_operation.xml
	disconnect
END
)

while [[ "$result" != "OK" ]]
do
  pyang -f sample-xml-skeleton --sample-xml-list-entries 2 *.yang
  
  result=$(netopeer2-cli <<-END
	connect --login netconf
	user-rpc --content=edit_config_operation.xml
	disconnect
END
)
done
echo "Finished loading data into sysrepo..."

exit 0