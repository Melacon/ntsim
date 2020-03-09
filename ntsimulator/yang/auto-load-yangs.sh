#!/bin/bash
################################################################################
#
# Copyright 2019 highstreet technologies GmbH and others
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

echo "Installing YANG models..."

set -eu -o pipefail

shopt -s failglob

: ${SYSREPOCTL:=sysrepoctl}
: ${SYSREPOCFG:=sysrepocfg}
: ${SYSREPOAPPSTART:=/opt/dev/sysrepo/build/examples/application_example}

declare -a excludedModules=()

# Uninstall the NTS Manager YANG model
$SYSREPOCTL -u -m network-topology-simulator
$SYSREPOCTL -u -m iana-if-type
$SYSREPOCTL -u -m ietf-ip
$SYSREPOCTL -u -m ietf-interfaces


sleep 5

pyang -f clearmust *.yang

mapfile -t modelList < <(pyang -f depend --depend-recurse *.yang)

for model in *.yang
do
  echo "Removing config false from $model..."
  sed -i '/config false;/d' $model
  echo "Removing mandatory true from $model..."
  sed -i '/mandatory true;/d' $model
done

if [ ${#modelList[@]} -eq 0 ]; then
  echo "No models present, nothing to do..."
  exit 0
else
  for model in ${modelList[@]}
  do
    modelName=${model%".yang"}
    
    skip_model=false
    
    for excluded in ${excludedModules[@]}; do
      if [ "$excluded" == "$modelName" ]; then
        skip_model=true
      fi
    done
    
    if [ "$skip_model" = true ]; then
      echo "Skipping installation of excluded model $modelName..."
      continue
    fi
    
    echo "Installing model: $model"
    $SYSREPOCTL --install --yang=$model --owner=root:root --permissions=666
    
	mapfile -t featureList < <(pyang -f listfeature $model)
  
    if [ ${#featureList[@]} -eq 0 ]; then
      echo "No features, nothing to do here..."
    else
      for feature in ${featureList[@]}
      do
        $SYSREPOCTL --feature-enable=$feature --module=$modelName
      done
    fi
    
    #if the YANG model contains only typedefs, we do not need to subscribe for datastore changes
    isTypeOnly=$(pyang -f listfeature --is-type-only $model)
    
    if [ "$isTypeOnly" == "False" ]; then
      printf "\n[program:$modelName]\ncommand=/opt/dev/sysrepo/build/examples/application_example $modelName\nautorestart=false\nredirect_stderr=true\nstartretries=1\npriority=4\n" >> /etc/supervisord.conf  
    fi
    
  done
fi

# Fix for the NETCONF notifications
echo "Fixing the NETCONF notifications..."
mkdir -p /var/run/sysrepo-subscriptions/ietf-crypto-types

echo "YANG models installation done!"

exit 0