#/bin/bash

echo "Cleaning up..."

mapfile -t NTS_containers < <( docker ps -a --filter "label=NTS" --format "{{.ID}}" )

CONTAINERS=""

if [ ${#NTS_containers[@]} -gt 0 ]
then

	for container in "${NTS_containers[@]}"
	do
		CONTAINERS="$CONTAINERS $container"
	done
	echo "Cleaning up ontainers: $CONTAINERS"
	docker kill $CONTAINERS > /dev/null 2>&1
	docker rm $CONTAINERS > /dev/null 2>&1
fi

echo "Cleaning NTS Manager container"
docker kill NTS_Manager > /dev/null 2>&1
docker rm NTS_Manager > /dev/null 2>&1

echo "All cleaned up!"
