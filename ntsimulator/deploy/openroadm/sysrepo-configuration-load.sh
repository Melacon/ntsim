#!/bin/bash

sleep 20

echo "Loading data into sysrepo..."

: ${SYSREPOCFG:=sysrepocfg}

pyang -f sample-xml-skeleton --sample-xml-list-entries 1 *.yang

mapfile -t modelList < <(ls -S -lr *.xml | awk {'print $9'})

if [ ${#modelList[@]} -eq 0 ]; then
  echo "No modules present, nothing to do..."
  exit 0
else
  for model in ${modelList[@]}
  do
    modelName=${model%".xml"}

    echo "Importing data for module: $model"
    $SYSREPOCFG --import=$model --format=xml $modelName
    
  done
fi

echo "Finished loading data into sysrepo..."

exit 0