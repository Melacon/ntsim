#!/bin/bash

if [ "$#" -eq 0 ]; then
    docker build --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') -t ntsim_openroadm_light -f ntsimulator/deploy/openroadm/Dockerfile .
    exit 0;
fi

if [ "$#" -eq 1 ]; then
    docker build --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') -t ntsim_openroadm_light -f ntsimulator/deploy/openroadm/Dockerfile .
    docker image tag ntsim_openroadm_light:latest 10.20.6.10:30000/hightec/ntsim_openroadm_device:$1-SNAPSHOT-latest
    echo "Successfully tagged ntsim_openroadm_light:latest to 10.20.6.10:30000/hightec/ntsim_openroadm_device:$1-SNAPSHOT-latest"
    exit 0;
fi
