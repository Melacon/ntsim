FROM ubuntu:18.04 AS builder

LABEL maintainer="alexandru.stancu@highstreet-technologies.com"

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
USER netconf
RUN \
      mkdir -p /home/netconf/.ssh && \
      ssh-keygen -A && \
      ssh-keygen -t dsa -P '' -f /home/netconf/.ssh/id_dsa && \
      cat /home/netconf/.ssh/id_dsa.pub > /home/netconf/.ssh/authorized_keys
#echo "Host *\n    StrictHostKeyChecking accept-new" >> /home/netconf/.ssh/config
USER root
RUN \
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
      cmake -DCMAKE_BUILD_TYPE:String="Release" -DKEYSTORED_KEYS_DIR=/home/netconf/.ssh .. && \
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
COPY ./ntsimulator/deploy/nts-manager/CMakeLists.txt /opt/dev/ntsimulator/CMakeLists.txt
RUN \
      cd /opt/dev && \
      cd ntsimulator && mkdir build  && cd build && \
      cmake .. && \
      make -j2 && \
      make install


# Second stage
FROM ubuntu:18.04  

LABEL maintainer="alexandru.stancu@highstreet-technologies.com"

ENV NETCONF_BASE=40000
ENV NTS_IP="127.0.0.1"
ENV SCRIPTS_DIR=/opt/dev/scripts
ENV DOCKER_ENGINE_VERSION="1.40"
ENV MODELS_IMAGE="ntsim_oran"
ENV VesHeartbeatPeriod=0
ENV IsVesAvailable=true
ENV IsNetconfAvailable=true
ENV VesRegistration=false
ENV VesEndpointPort=8080
ENV VesEndpointIp="172.17.0.1"
ENV SshConnections=1
ENV TlsConnections=0
ENV K8S_DEPLOYMENT=false
ENV CONTAINER_NAME="ntsim"

RUN \
      apt-get update && apt-get install -y supervisor bc

# add netconf user
RUN \
      adduser --system netconf && \
      echo "netconf:netconf" | chpasswd

USER netconf
# generate ssh keys for netconf user
RUN \
      mkdir -p /home/netconf/.ssh

COPY --from=builder /home/netconf/.ssh /home/netconf/.ssh

USER root
COPY --from=builder /etc/ssh /etc/ssh
COPY --from=builder /root/.ssh /root/.ssh
COPY --from=builder /usr/local/lib /usr/local/lib
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --from=builder /usr/local/include /usr/local/include
COPY --from=builder /usr/lib/libavl.so /usr/lib/libavl.so
COPY --from=builder /usr/lib/libavl.so.1 /usr/lib/libavl.so.1
COPY --from=builder /usr/lib/x86_64-linux-gnu/libev.so /usr/lib/x86_64-linux-gnu/libev.so
COPY --from=builder /usr/lib/x86_64-linux-gnu/libev.so.4 /usr/lib/x86_64-linux-gnu/libev.so.4
COPY --from=builder /usr/lib/x86_64-linux-gnu/libcurl.so.4 /usr/lib/x86_64-linux-gnu/libcurl.so.4
COPY --from=builder /usr/lib/x86_64-linux-gnu/libcurl.so /usr/lib/x86_64-linux-gnu/libcurl.so
COPY --from=builder /usr/lib/x86_64-linux-gnu/libcurl-gnutls.so.4 /usr/lib/x86_64-linux-gnu/libcurl-gnutls.so.4
COPY --from=builder /usr/lib/x86_64-linux-gnu/libcjson_utils.so.1 /usr/lib/x86_64-linux-gnu/libcjson_utils.so.1
COPY --from=builder /usr/lib/x86_64-linux-gnu/libcjson_utils.so /usr/lib/x86_64-linux-gnu/libcjson_utils.so
COPY --from=builder /usr/lib/x86_64-linux-gnu/libcjson.so.1 /usr/lib/x86_64-linux-gnu/libcjson.so.1 
COPY --from=builder /usr/lib/x86_64-linux-gnu/libcjson.so /usr/lib/x86_64-linux-gnu/libcjson.so
COPY --from=builder /usr/lib/x86_64-linux-gnu/libprotobuf.so.10 /usr/lib/x86_64-linux-gnu/libprotobuf.so.10
COPY --from=builder /usr/lib/x86_64-linux-gnu/libprotobuf-c.so.1 /usr/lib/x86_64-linux-gnu/libprotobuf-c.so.1
COPY --from=builder /usr/lib/x86_64-linux-gnu/libprotobuf-c.so /usr/lib/x86_64-linux-gnu/libprotobuf-c.so
COPY --from=builder /usr/lib/x86_64-linux-gnu/libssh_threads.so.4 /usr/lib/x86_64-linux-gnu/libssh_threads.so.4
COPY --from=builder /usr/lib/x86_64-linux-gnu/libssh_threads.so /usr/lib/x86_64-linux-gnu/libssh_threads.so
COPY --from=builder /usr/lib/x86_64-linux-gnu/libssh.so.4 /usr/lib/x86_64-linux-gnu/libssh.so.4
COPY --from=builder /usr/lib/x86_64-linux-gnu/libssh.so /usr/lib/x86_64-linux-gnu/libssh.so
COPY --from=builder /usr/lib/x86_64-linux-gnu/libnghttp2.so.14 /usr/lib/x86_64-linux-gnu/libnghttp2.so.14
COPY --from=builder /usr/lib/x86_64-linux-gnu/librtmp.so.1 /usr/lib/x86_64-linux-gnu/librtmp.so.1
COPY --from=builder /usr/lib/x86_64-linux-gnu/libpsl.so.5 /usr/lib/x86_64-linux-gnu/libpsl.so.5
COPY --from=builder /usr/lib/x86_64-linux-gnu/libgssapi_krb5.so.2 /usr/lib/x86_64-linux-gnu/libgssapi_krb5.so.2
COPY --from=builder /usr/lib/x86_64-linux-gnu/libldap_r-2.4.so.2 /usr/lib/x86_64-linux-gnu/libldap_r-2.4.so.2
COPY --from=builder /usr/lib/x86_64-linux-gnu/liblber-2.4.so.2 /usr/lib/x86_64-linux-gnu/liblber-2.4.so.2
COPY --from=builder /usr/lib/x86_64-linux-gnu/libkrb5.so.3 /usr/lib/x86_64-linux-gnu/libkrb5.so.3
COPY --from=builder /usr/lib/x86_64-linux-gnu/libk5crypto.so.3 /usr/lib/x86_64-linux-gnu/libk5crypto.so.3
COPY --from=builder /usr/lib/x86_64-linux-gnu/libkrb5support.so.0 /usr/lib/x86_64-linux-gnu/libkrb5support.so.0
COPY --from=builder /usr/lib/x86_64-linux-gnu/libsasl2.so.2 /usr/lib/x86_64-linux-gnu/libsasl2.so.2
COPY --from=builder /usr/lib/x86_64-linux-gnu/libgssapi.so.3 /usr/lib/x86_64-linux-gnu/libgssapi.so.3
COPY --from=builder /usr/lib/x86_64-linux-gnu/libheimntlm.so.0 /usr/lib/x86_64-linux-gnu/libheimntlm.so.0
COPY --from=builder /usr/lib/x86_64-linux-gnu/libkrb5.so.26 /usr/lib/x86_64-linux-gnu/libkrb5.so.26
COPY --from=builder /usr/lib/x86_64-linux-gnu/libasn1.so.8 /usr/lib/x86_64-linux-gnu/libasn1.so.8
COPY --from=builder /usr/lib/x86_64-linux-gnu/libhcrypto.so.4 /usr/lib/x86_64-linux-gnu/libhcrypto.so.4
COPY --from=builder /usr/lib/x86_64-linux-gnu/libroken.so.18 /usr/lib/x86_64-linux-gnu/libroken.so.18
COPY --from=builder /usr/lib/x86_64-linux-gnu/libwind.so.0 /usr/lib/x86_64-linux-gnu/libwind.so.0
COPY --from=builder /usr/lib/x86_64-linux-gnu/libheimbase.so.1 /usr/lib/x86_64-linux-gnu/libheimbase.so.1
COPY --from=builder /usr/lib/x86_64-linux-gnu/libhx509.so.5 /usr/lib/x86_64-linux-gnu/libhx509.so.5

COPY --from=builder /lib/x86_64-linux-gnu/libkeyutils.so.1 /lib/x86_64-linux-gnu/libkeyutils.so.1
COPY --from=builder /etc/sysrepo /etc/sysrepo
COPY --from=builder /var/run /var/run

#COPY --from=builder /usr/local/etc/keystored/keys/ssh_host_rsa_key.pem /usr/local/etc/keystored/keys/ssh_host_rsa_key.pem
#COPY --from=builder /usr/local/etc/keystored/keys/ssh_host_rsa_key.pem.pub /usr/local/etc/keystored/keys/ssh_host_rsa_key.pem.pub
COPY --from=builder /usr/local/share/libnetconf2 /usr/local/share/libnetconf2

RUN ldconfig

COPY ntsimulator/deploy/nts-manager/supervisord.conf /etc/supervisord.conf

COPY ntsimulator/deploy/nts-manager/docker_stats.sh /opt/dev/docker_stats.sh

# Fix for the NETCONF notifications
RUN \
    echo "Fixing the NETCONF notifications..." && \
    mkdir -p /var/run/sysrepo-subscriptions/ietf-crypto-types
	  
ARG BUILD_DATE
LABEL build-date=$BUILD_DATE

ENV EDITOR vim
EXPOSE 830

CMD ["sh", "-c", "/usr/bin/supervisord -c /etc/supervisord.conf"]
