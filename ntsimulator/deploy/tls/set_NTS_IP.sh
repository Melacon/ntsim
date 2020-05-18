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

sleep 30

if [ "$K8S_DEPLOYMENT" = "true" ]; then
   NTS_IP=""
   while true
    do
        echo "Trying to set the NTS_IP env var..."
        if [ -z "$NTS_IP" ]; then
            s=$HOSTNAME
            count="$(cut -d'-' -f2 <<<"$s")"
            id="NTSIM_${count}_SERVICE_HOST"
            export NTS_IP=$(echo ${!id})
            echo "NTS_IP=$NTS_IP"
        else
            echo "export NTS_IP=$NTS_IP" >> /root/.bashrc
            source /root/.bashrc
        fi
        sleep 10
    done
else
  echo "Non k8s deployment, not doing anything for the NTS_IP..."
fi

exit 0
