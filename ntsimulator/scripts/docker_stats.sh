#!/bin/bash
################################################################################
#
# Copyright 2020 highstreet technologies GmbH and others
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
################################################################################

# This script is used to complete the output of the docker stats command.
# The docker stats command does not compute the total amount of resources (RAM or CPU)

# Get the output of the docker stat command. Will be displayed at the end
# Without modifying the special variable IFS the ouput of the docker stats command won't have
CPU_CORES=`nproc`
# the new lines thus resulting in a failure when using awk to process each line
IFS=;
mapfile -t DOCKER_PS_RESULT < <(/usr/bin/docker ps --all --format "{{.ID}}" --filter "label=NTS")

CONTAINERS=""

if [ ${#DOCKER_PS_RESULT[@]} -gt 0 ]
then

	for container in "${DOCKER_PS_RESULT[@]}"
	do
		CONTAINERS="$CONTAINERS $container"
	done
fi

if [ -z "$CONTAINERS" ]
then
	CPU_SCALED=0
	SUM_RAM=0
else
	DOCKER_STATS_COMMAND="/usr/bin/docker stats --no-stream --format \"table {{.CPUPerc}}\t{{.MemUsage}}\" ${CONTAINERS}"
	DOCKER_STATS_COMMAND_RESULT=$(eval "$DOCKER_STATS_COMMAND")

	SUM_CPU=`echo $DOCKER_STATS_COMMAND_RESULT | tail -n +2 | sed "s/%//g" | awk '{s+=$1} END {print s}'`
	SUM_RAM=`echo $DOCKER_STATS_COMMAND_RESULT | tail -n +2 | sed "s/%//g" | awk '{s+=$2} END {print s}'`

	CPU_SCALED=$(echo "scale=2; $SUM_CPU/$CPU_CORES" | bc)
fi

# Output the result
echo -e "CPU=${CPU_SCALED}%;RAM=${SUM_RAM}MiB"