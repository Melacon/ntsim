docker build --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') -t ntsim_xran_light -f ntsimulator/deploy/x-ran/Dockerfile .

