#!/bin/bash

sleep 3

set -eu -o pipefail

shopt -s failglob

: ${SYSREPOCTL:=sysrepoctl}

echo "- Uninstalling microwave-model..."
$SYSREPOCTL --uninstall --module=microwave-model

echo "- Uninstalling core-model..."
$SYSREPOCTL --uninstall --module=core-model

exit 0