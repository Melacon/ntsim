#!/bin/bash

echo "Loading config data into the NETCONF Server..."

result=$(netopeer2-cli <<-END
	connect --host 127.0.0.1 --login netconf
	user-rpc --content=/opt/dev/edit-config-after-activate.xml
	disconnect
END
)

echo $result
echo "Done!"

exit 0
