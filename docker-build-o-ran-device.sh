docker build --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') -t ntsim_oran -f ntsimulator/deploy/o-ran/Dockerfile .

