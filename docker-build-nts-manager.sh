#!/bin/bash

if [ "$#" -eq 0 ]; then
    docker build --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') -t ntsim_manager_light -f ntsimulator/deploy/nts-manager/Dockerfile .
    exit 0;
fi

if [ "$#" -eq 1 ]; then
    docker build --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') -t ntsim_manager_light -f ntsimulator/deploy/nts-manager/Dockerfile .
    docker image tag ntsim_manager_light:latest 10.20.6.10:30000/hightec/ntsim_manager:$1-SNAPSHOT-latest
    echo "Successfully tagged ntsim_manager_light:latest to 10.20.6.10:30000/hightec/ntsim_manager:$1-SNAPSHOT-latest"
    exit 0;
fi