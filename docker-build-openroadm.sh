docker build --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') -t ntsim_openroadm_light -f ntsimulator/deploy/openroadm/Dockerfile .

