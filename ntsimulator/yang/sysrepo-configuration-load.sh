#!/bin/bash

sleep 20

echo "Loading data into sysrepo..."

ssh-keyscan -p 830 127.0.0.1 >> ~/.ssh/known_hosts

result=$(netopeer2-cli <<-END
	knownhosts --del 0
    knownhosts --del 0
END
)

pyang -f sample-xml-skeleton --sample-xml-list-entries 2 *.yang

result=$(netopeer2-cli <<-END
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