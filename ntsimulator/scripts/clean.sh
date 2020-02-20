#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "ID Parameter missing."
	echo "Usage: $0 id
	
where id is the docker container id of the NTS Manager instance that we want to clean. "
	exit 1
fi

echo "Cleaning up containers started by the NTS Manager $1..."

mapfile -t NTS_containers < <( docker ps -a --filter "label=NTS_Manager=$1" --format "{{.ID}}" )

CONTAINERS=""

if [ ${#NTS_containers[@]} -gt 0 ]
then

	for container in "${NTS_containers[@]}"
	do
		CONTAINERS="$CONTAINERS $container"
	done
	echo "Cleaning up containers: $CONTAINERS"
	docker kill $CONTAINERS > /dev/null 2>&1
	docker rm $CONTAINERS > /dev/null 2>&1
fi

echo "Cleaning NTS Manager $1..."
docker kill $1 > /dev/null 2>&1
docker rm $1 > /dev/null 2>&1

echo "All cleaned up!"
