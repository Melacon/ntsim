#!/bin/bash

if [ "$#" -eq 0 ]; then
    docker build --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') -t ntsim_oran_sc_oran_ru_light -f ntsimulator/deploy/o-ran-sc/o-ran-ru/Dockerfile .
    exit 0;
fi

if [ "$#" -eq 1 ]; then
    docker build --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') -t ntsim_oran_sc_oran_ru_light -f ntsimulator/deploy/o-ran-sc/o-ran-ru/Dockerfile .
    docker image tag ntsim_oran_sc_oran_ru_light:latest 10.20.6.10:30000/hightec/ntsim_oran_sc_oran_ru_light:$1-SNAPSHOT-latest
    echo "Successfully tagged ntsim_oran_sc_oran_ru_light:latest to 10.20.6.10:30000/hightec/ntsim_oran_sc_oran_ru_light:$1-SNAPSHOT-latest"
    exit 0;
fi

