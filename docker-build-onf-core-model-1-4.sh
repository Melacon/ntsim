#!/bin/bash

if [ "$#" -eq 0 ]; then
    docker build --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') -t ntsim_onf_core_model_1_4 -f ntsimulator/deploy/onf/core-model-1-4/Dockerfile .
    exit 0;
fi

if [ "$#" -eq 1 ]; then
    docker build --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') -t ntsim_onf_core_model_1_4 -f ntsimulator/deploy/onf/core-model-1-4/Dockerfile .
    docker image tag ntsim_onf_core_model_1_4:latest 10.20.6.10:30000/hightec/ntsim_onf_core_model_1_4:$1-SNAPSHOT-latest
    echo "Successfully tagged ntsim_onf_core_model_1_4:latest to 10.20.6.10:30000/hightec/ntsim_onf_core_model_1_4:$1-SNAPSHOT-latest"
    exit 0;
fi
