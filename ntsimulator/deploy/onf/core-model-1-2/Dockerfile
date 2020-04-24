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
      bc

RUN \
      apt-get install -y \
      python-setuptools \
      python-pip

# pyang dependencies
RUN pip install rstr && \
    pip install exrex && \
    pip install ipaddress && \
    pip install lxml

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

# pyang
COPY ./pyang /opt/dev/pyang
RUN \
	  cd /opt/dev && \
	  cd pyang && python setup.py build && python setup.py install

# NTSimulator device
COPY ./ntsimulator /opt/dev/ntsimulator
COPY ./ntsimulator/deploy/onf/core-model-1-2/CMakeLists.txt /opt/dev/ntsimulator/src/CMakeLists.txt
RUN \
      cd /opt/dev && \
      cd ntsimulator && mkdir build  && cd build && \
      cmake .. && \
      make -j2 && \
      make install

# Second stage
FROM ubuntu:18.04  

LABEL maintainer="alexandru.stancu@highstreet-technologies.com"

RUN \
      apt-get update && apt-get install -y supervisor

# add netconf user
RUN \
      adduser --system netconf && \
      echo "netconf:netconf" | chpasswd

# generate ssh keys for netconf user
RUN \
      mkdir -p /home/netconf/.ssh

COPY --from=builder /home/netconf/.ssh /home/netconf/.ssh
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

COPY --from=builder /usr/local/etc/keystored/keys/ssh_host_rsa_key.pem /usr/local/etc/keystored/keys/ssh_host_rsa_key.pem
COPY --from=builder /usr/local/etc/keystored/keys/ssh_host_rsa_key.pem.pub /usr/local/etc/keystored/keys/ssh_host_rsa_key.pem.pub
COPY --from=builder /usr/local/share/libnetconf2 /usr/local/share/libnetconf2

RUN ldconfig

WORKDIR /tmp
RUN apt-get install -yqq wget \
    openssh-client \
    jq

RUN mkdir py_install && cd py_install && \
    wget https://files.pythonhosted.org/packages/b9/9a/3e9da40ea28b8210dd6504d3fe9fe7e013b62bf45902b458d1cdc3c34ed9/ipaddress-1.0.23.tar.gz && \
    tar -xvzf ipaddress-1.0.23.tar.gz && cd ipaddress-1.0.23 && \
    python setup.py install

COPY --from=builder /etc/ssh /etc/ssh
COPY --from=builder /root/.ssh /root/.ssh

WORKDIR /opt/dev
# run only specific programs in this image
COPY ./ntsimulator/deploy/onf/core-model-1-2/supervisord.conf /etc/supervisord.conf

# tls configuratoin
COPY ./ntsimulator/deploy/tls /home/netconf/.ssh

COPY --from=builder /opt/dev/sysrepo/build/examples/application_example /opt/dev/sysrepo/build/examples/application_example

# YANG models and related scripts
COPY ./ntsimulator/yang/onf/core-model-1-2 /opt/dev/yang
COPY ./ntsimulator/yang/auto-load-yangs.sh /opt/dev/yang
COPY ./ntsimulator/yang/sysrepo-configuration-load.sh /opt/dev/yang
WORKDIR /opt/dev
RUN \
	  cd yang && \
	  ./auto-load-yangs.sh

ARG BUILD_DATE
LABEL build-date=$BUILD_DATE
	  
ENV EDITOR vim
EXPOSE 830-839

CMD ["sh", "-c", "/usr/bin/supervisord -c /etc/supervisord.conf"]
