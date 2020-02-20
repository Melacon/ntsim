docker build --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') -t ntsim_oransc_nearrtric -f ntsimulator/deploy/Dockerfile .
