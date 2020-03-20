docker build --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') -t ntsim_onf_core_model_1_2 -f ntsimulator/deploy/onf/core-model-1-2/Dockerfile .

