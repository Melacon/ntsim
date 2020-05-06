#!/bin/bash

if [ "$#" -eq 0 ]; then
    docker build --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') -t ntsim_xran_light -f ntsimulator/deploy/x-ran/Dockerfile .
    exit 0;
fi

if [ "$#" -eq 1 ]; then
    docker build --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') -t ntsim_xran_light -f ntsimulator/deploy/x-ran/Dockerfile .
    docker image tag ntsim_xran_light:latest 10.20.6.10:30000/hightec/ntsim_xran:$1-SNAPSHOT-latest
    echo "Successfully tagged ntsim_xran_light:latest to 10.20.6.10:30000/hightec/ntsim_xran:$1-SNAPSHOT-latest"
    exit 0;
fi
