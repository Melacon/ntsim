#!/bin/bash

sleep 20

echo "Loading data into sysrepo..."

: ${SYSREPOCFG:=sysrepocfg}

model="org-openroadm-device"

echo "Importing data for module: $model"
$SYSREPOCFG --import=/opt/dev/scripts/startup-load.xml --format=xml $model

echo "Finished loading data into sysrepo..."

exit 0