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
FROM ubuntu:18.04

MAINTAINER alexandru.stancu@highstreet-technologies.com
LABEL maintainer="alexandru.stancu@highstreet-technologies.com"

#ARG BUILD_DATE
#LABEL build-date=$BUILD_DATE

ENV NETCONF_BASE=40000
ENV NTS_IP="0.0.0.0"
ENV SCRIPTS_DIR=/opt/dev/scripts
ENV DOCKER_ENGINE_VERSION="1.40"
ENV MODELS_IMAGE="ntsim_oran"

RUN \
      apt-get update && apt-get install -y \
      # general tools
      git \
      cmake \
      build-essential \
      vim \
      supervisor \
      # libyang
      libpcre3-dev \
      pkg-config \
      # sysrepo
      libavl-dev \
      libev-dev \
      libprotobuf-c-dev \
      protobuf-c-compiler \
      # netopeer2 \
      libssh-dev \
      libssl-dev \
      # bindings
      swig \
      python-dev \
      libcurl4 \
      libcurl4-openssl-dev \
      curl \
      bc \
      python-setuptools \
      python-pip

# add netconf user
RUN \
      adduser --system netconf && \
      echo "netconf:netconf" | chpasswd

# generate ssh keys for netconf user
RUN \
      mkdir -p /home/netconf/.ssh && \
      ssh-keygen -A && \
      ssh-keygen -t dsa -P '' -f /home/netconf/.ssh/id_dsa && \
      cat /home/netconf/.ssh/id_dsa.pub > /home/netconf/.ssh/authorized_keys && \
#echo "Host *\n    StrictHostKeyChecking accept-new" >> /home/netconf/.ssh/config
      echo "    StrictHostKeyChecking no" >> /etc/ssh/ssh_config && \
      mkdir -p /root/.ssh && \
      cat /home/netconf/.ssh/id_dsa.pub > /root/.ssh/authorized_keys
       
# use /opt/dev as working directory
RUN mkdir /opt/dev
WORKDIR /opt/dev

# libcjson
COPY ./cJSON /opt/dev/cJSON
RUN \
      cd cJSON && mkdir build && cd build && \
      cmake .. -DENABLE_CJSON_UTILS=On -DENABLE_CJSON_TEST=Off -DCMAKE_INSTALL_PREFIX=/usr .. && \
      make -j2 && \
      make install && \
      ldconfig

# libyang
COPY ./libyang /opt/dev/libyang
RUN \
      cd libyang && mkdir build && cd build && \
      cmake -DCMAKE_BUILD_TYPE:String="Release" -DENABLE_BUILD_TESTS=OFF .. && \
      make -j2 && \
      make install && \
      ldconfig

# sysrepo
COPY ./sysrepo /opt/dev/sysrepo
RUN \
      sed -i 's/#define MAX_BLOCKS_AVAIL_FOR_ALLOC    3/#define MAX_BLOCKS_AVAIL_FOR_ALLOC    6/g' ./sysrepo/src/common/sr_mem_mgmt.h && \
      cd sysrepo && mkdir build && cd build && \
      cmake -DCMAKE_BUILD_TYPE:String="Release" -DENABLE_TESTS=OFF -DREPOSITORY_LOC:PATH=/etc/sysrepo -DREQUEST_TIMEOUT=60 -DOPER_DATA_PROVIDE_TIMEOUT=60 .. && \
      make -j2 && \
      make install && \
      ldconfig

# libnetconf2
COPY ./libnetconf2 /opt/dev/libnetconf2
RUN \
      cd libnetconf2 && mkdir build && cd build && \
      cmake -DCMAKE_BUILD_TYPE:String="Release" -DENABLE_BUILD_TESTS=OFF .. && \
      make -j2 && \
      make install && \
      ldconfig

# keystore
COPY ./Netopeer2 /opt/dev/Netopeer2
RUN \
      cd /opt/dev && \
      cd Netopeer2 && \
      cd keystored && mkdir build && cd build && \
      cmake -DCMAKE_BUILD_TYPE:String="Release" .. && \
      make -j2 && \
      make install && \
      ldconfig

# netopeer2
RUN \
      cd /opt/dev && \
      cd Netopeer2/server && mkdir build && cd build && \
      cmake -DCMAKE_BUILD_TYPE:String="Release" .. && \
      make -j2 && \
      make install && \
      cd ../../cli && mkdir build && cd build && \
      cmake -DCMAKE_BUILD_TYPE:String="Release" .. && \
      make -j2 && \
      make install

#NTSimulator Manager
COPY ./ntsimulator /opt/dev/ntsimulator
RUN \
      cd /opt/dev && \
      cd ntsimulator && mkdir build  && cd build && \
      cmake .. && \
      make -j2 && \
      make install

COPY ntsimulator/deploy/manager/supervisord.conf.manager /etc/supervisord.conf

# Fix for the NETCONF notifications
RUN \
      echo "Fixing the NETCONF notifications..." && \
      mkdir -p /var/run/sysrepo-subscriptions/ietf-crypto-types
	  
ENV EDITOR vim
EXPOSE 830

CMD ["sh", "-c", "/usr/bin/supervisord -c /etc/supervisord.conf"]
