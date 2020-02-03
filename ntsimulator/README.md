# Network Topology Simulator (NTS)

The Network Topology Simulator is a framework that allows simulating devices that expose a management interface through a NETCONF/YANG interface.

## Description

### Overview

The NETCONF/YANG management interface is simulated, and any YANG models can be loaded by the framework to be exposed. Random data is generated based on the specific models, such that each simulated device presents different data on its management interface.

The NTS Manager can be used to specify the simulation details and to manage the simulation environment at runtime.

The NTS framework is based on several open-source projects:
* [Netopeer2](https://github.com/CESNET/Netopeer2) 
* [libnetconf2](https://github.com/CESNET/libnetconf2) 
* [libyang](https://github.com/CESNET/libyang)
* [sysrepo](https://github.com/sysrepo/sysrepo) - all of these are used for the implementation of the NETCONF Server, both in the NTS Manager and in each simulated device
* [cJSON](https://github.com/DaveGamble/cJSON) - used to create the JSON payloads for talking with the simulation framework
* [pyang](https://github.com/mbj4668/pyang) - used to create random data from the YANG models that are exposed

Each simulated device is represented as a docker container, where the NETCONF Server is running. The creation and deletion of docker containers associated with simulated devices is handled by the NTS Manager. The NTS Manager is also running as a docker container and exposes a NETCONF/YANG interface to control the simulation.

### NTS Manager

The purpose of the NTS Manager is to ease the utilization of the NTS framework. It enables the user to interact with the simulation framework through a NETCONF/YANG interface. The user has the ability to modify the simulation parameters at runtime and to see the status of the current state of the NTS. The NETCONF/YANG interface will be detailed below.

```
module: network-topology-simulator
  +--rw simulator-config
  |  +--rw simulated-devices?      uint32
  |  +--rw mounted-devices?        uint32
  |  +--rw notification-config
  |  |  +--rw fault-notification-delay-period?   uint32
  |  |  +--rw ves-heartbeat-period?              uint32
  |  |  +--rw is-netconf-available?              boolean
  |  |  +--rw is-ves-available?                  boolean
  |  +--rw controller-details
  |  |  +--rw controller-ip?         inet:ip-address
  |  |  +--rw controller-port?       inet:port-number
  |  |  +--rw controller-username?   string
  |  |  +--rw controller-password?   string
  |  +--rw ves-endpoint-details
  |     +--rw ves-endpoint-ip?            inet:ip-address
  |     +--rw ves-endpoint-port?          inet:port-number
  |     +--rw ves-endpoint-auth-method?   authentication-method-type
  |     +--rw ves-endpoint-username?      string
  |     +--rw ves-endpoint-password?      string
  |     +--rw ves-endpoint-certificate?   string
  |     +--rw ves-registration?           boolean
  +--ro simulator-status
     +--ro simulation-usage-details
     |  +--ro running-simulated-devices?   uint32
     |  +--ro running-mounted-devices?     uint32
     |  +--ro base-netconf-port?           uint32
     |  +--ro cpu-usage?                   percent
     |  +--ro mem-usage?                   uint32
     +--ro simulated-devices-list* [uuid]
        +--ro uuid                 string
        +--ro device-ip?           string
        +--ro device-port*         uint32
        +--ro is-mounted?          boolean
        +--ro operational-state?   operational-state-type

  rpcs:
    +---x restart-simulation
    +---x add-key-pair-to-odl
```

#### Detailed information about the YANG attributes

##### Configuration

* **simulated-devices** - represents the number of simulated devices. The default value is 0, meaning that when the NTS is started, there are no simulated devices. When this value is increased to **n**, the NTS Manager starts docker containers in order to reach **n** simulated devices. If the value is decreased to **k**, the NTS Manager will remove docker containers, until the number of simulated devices reaches **k**;
* **mounted-devices** - represents the number of devices to be mounted to an ODL based SDN Controller. The same phylosophy as in the case of the previous leaf applies. If this number is increased, the number of ODL mountpoints increases. Else, the simulated devices are being unmounted from ODL. The number of mounted devices cannot exceed the number of simulated devices. The details about the ODL controller where to mount/unmount are given by the **controller-details** container; **Please note that this cannot be set to a value > 0 if the *ves-registration* leaf is set to 'True'**; For each simulated device, 10 NETCONF endpoints will be mounted (7 SSH + 3 TLS). See **NETCONF Endpoints** section for more details.
*  **notification-config** - this container groups the configuration about fault notification generation of each simulated device;
* **fault-notification-delay-period** - the amount of seconds between two generated fault notifications. For example, if this has a value of *10*, each simulated device will generate a **random** fault notification every *10* seconds;
* **ves-heartbeat-period** - the amount of seconds between VES heartbeat messages that can be generated by each simulated device. The details about the VES connection endpoint are given in the **ves-endpoint-details** container;
* **is-netconf-available** - if set to 'True', NETCONF notifications will be sent when a random fault notification is generated, The NETCONF notification that is being sent is currently *o-ran-fm:alarm-notif*; if set to 'False', NETCONF notifications are not being sent out;
* **is-ves-available** - if set to 'True', VES *faultNotification* messages will be sent when a random fault notification is generated; if set to 'False', VES *faultNotification* messages are not generated;
* **controller-details** - this container groups the configuration related to the ODL based SDN controller that the simulated devices can connect to;
* **controller-ip** - the IP address of the ODL based SDN controller where the simulated devices can be mounted. Only IPv4 is supported currently;
* **controller-port** - the port of the ODL based SDN controller;
* **controller-username** - the username to be used when connecting to the ODL based SDN controller;
* **controller-password** - the password to be used when connecting to the ODL based SDN controller;
* **ves-endpoint-details** - this container groups the configuration related to the VES endpoint where the VES messages are targeted;
* **ves-endpoint-ip** - the IP address of the VES endpoint where VES messages are targeted;
* **ves-endpoint-port** - the port address of the VES endpoint where VES messages are targeted;
* **ves-endpoint-auth-method** - the authentication method to be used when sending the VES message to the VES endpoint. Possible values are:
  + *no-auth* - no authentication;
  + *cert-only* - certificate only authentication; in this case the certificate to be used for the communication must be configured;
  + *basic-auth* - classic username/password authentication; in this case both the username and password need to be configured;
  + *cert-basic-auth* - authentication that uses both username/password and a certificate; all three values need to be configured in this case;
* **ves-endpoint-username** - the username to be used when authenticating to the VES endpoint;
* **ves-endpoint-password** - the password to be used when authenticating to the VES endpoint;
* **ves-endpoint-certificate** - the certificate to be used when authenticating to the VES endpoint;
* **ves-registration** - if this is set to 'True' **when simulated devices are starting**, each simulated device will send out *pnfRegistration* VES messages to the configured VES endpoint; if this is set to 'False', *pnfRegistration* VES messages will not be sent out. **Please note that this cannot be set to 'True' is simulated devices are already mounted to ODL based SDN controller (mounted-devices leaf > 0)**; For each simulated device, 10 pnfRegistration VES messages will be sent out (7 SSH + 3 TLS). See **NETCONF Endpoints** section for more details.

##### Status

* **simulation-usage-details** - this container groups the information about the current simulator status;
* **running-simulated-devices** - the current number of running simulated devices;
* **running-mounted-devices** - the current number of running simulated devices that have been mounted to the ODL based SDN controller; For each simulated device, 10 NETCONF endpoints will be mounted (7 SSH + 3 TLS). See **NETCONF Endpoints** section for more details.
* **base-netconf-port** - the port that was used as a base when craeting simulated devices;
* **cpu-usage** - the percentage of the CPU used currently by the simulation framework;
* **mem-usage** - the amount of RAM used (in MB) currently by the simulation framework;
* **simulated-devices-list** - this list contains the details about each simulated devices that is currently running;
* **uuid** - the Universally Unique ID of the simulated device;
* **device-ip** - the IP address of the simulated device;
* **device-port** - the port of the simulated device, where the NETCONF connection is exposed;
* **is-mounted** - boolean to show whether the device is currently mounted to an ODL based SDN controller;
* **operational-state** - the operational state of the current simulated device; it can be either *not-specified*, *created*, *running* or *exited*.

##### RPCs

* **add-key-pair-to-odl** - this RPC can be used to trigger the loading of a *keystore* entry in an ODL based SDN controller such that the controller can connect to the simulated devices via **TLS**. A private key, an associated certificate and a trusted certificate are loaded in the *keystore* entry in ODL. The certificate associated with the private key to be used by ODL in the TLS communication is signed by the same CA as the certificates used by the simulated devices, easing the TLS configuration in both the NETCONF Server and the ODL.
* **restart-simulation** - this RPC is not yet implemented.

### Simulated Device

Each simulated device is represented as a docker container, inside which the NETCONF Server runs. The simulated device exposes the YANG models which are found inside the **yang** folder. A custom version of the *pyang* utility is used to generate random data for each of the YANG modules found inside the **yang** folder.

#### NETCONF Endpoints

Each simulated device exposes **10 NETCONF endpoints**, on 10 consecutive ports. The first simulated device uses the 10 ports starting from the **NETCONF_BASE** environment variable used when starting the NTST Manager, while the nextt one uses the next 10 ports and so on and so forth. E.g. if the **NETCONF_BASE=50000** the first simulated device will expose ports from *50000* to *50009*, the second simulated device will expose ports from *50010* to *50019* etc.

The first 7 connections exposed by a simulated device are **SSH** based. A NETCONF client can connect to the exposed endpoint using one of the SSH ports (e.g. 50000 to 50006) and the **username/password**: *netconf/netconf*.

The last 3 connections exposed by a simulated device are **TLS** based. A NETCONF client can connect to the exposed endpoint using one of the TLS ports (e.g. 50007 to 50009), using a valid certificate and the **username**: *netconf*. 

## Usage

### Building the images

The `docker-build-manager.sh` script can be used to built the docker image associated with the NTS Manager. This will create a docker image named *ntsim_manager*, which will be used to start the simulation framework. Inside the docker image, port 830 will wait for connections for the NETCONF/YANG management interface.

The `docker-build-model.sh` script can be used to build the docker image associated with a simulated device. Currently, this will create a docker image named *ntsim_oran*, which will be used by the manager to start the docker containers for each simulated device.

### Starting the NTS Manager

The NTS Manager can be started using the `docker-compose.yml` file that is provided inside tthe **scripts** folder. Further, the parameters present in this file are explained.

```yaml
version: '3'
services:
  ntsimulator:
    image: "ntsim_manager:latest"
    container_name: NTS_Manager
    ports:
     - "172.17.0.1:8300:830"
    volumes:
     - "/var/run/docker.sock:/var/run/docker.sock"
     - "/path/to/simulator/folder/ntsimulator/scripts:/opt/dev/scripts"
     - "/usr/bin/docker:/usr/bin/docker"
    labels:
      "NTS-manager": ""
    environment:
      NTS_IP: "172.17.0.1"
      NETCONF_BASE: 50000
      DOCKER_ENGINE_VERSION: "1.40"
      MODELS_IMAGE: "ntsim_oran"
```


* Port mapping:
    * `"172.17.0.1:8300:830"` - this maps the *830* port from inside the docker container of the NTS Manager to the port *8300* from the host, and binds it to the docker IP address *172.17.0.1*:
    
* Volumes - these map 3 important things:
    * the docker socket from the host is mapped inside the docker container:
        `/var/run/docker.sock:/var/run/docker.sock` - **please do not modify the path inside the container!**;
    * the **scripts** folder from the cloned repository needs to be mapped inside the container:
        `/path/to/simulator/folder/ntsimulator/scripts:/opt/dev/scripts` - **please do not modify the path inside the container!**;
    * the path to the docker executable needs to be mapped inside the container:
        `/usr/bin/docker:/usr/bin/docker` - **please do not modify the path inside the container!**;
        
* Labels - this associates the *NTS-manager* label to the docker container where the NTS runs;
* Environment variables:
    * **NTS_IP** - this should point to an IP address **from the host**, through which the simulated devices will be accessed;
    * **NETCONF_BASE** - this is the starting port used to expose NETCONF endpoints. Starting from this, each device will use 10 consecutive ports for its endpoints;
    * **DOCKER_ENGINE_VERSION** - this is the version of the *docker engine* installed currently on the host. This can be verified using `docker version` command in the host, and looking to the `API version:      #.##` variable from the Server details.
    * **MODELS_IMAGE** - this represents the name of the docker image that represents the simulated device. The NTS Manager will start containers using this image, when starting simulated devices.
    
After modifying the `docker-compose.yml` file with values specific to your host, the NTS Manager can be started by running the command `docker-compose up` from the **scripts** folder.

After the NTS Manager is started, it will wait for connections on its NETCONF/YANG management interface. One can connect to this using a NETCONF Client. The **username/password** for connecting are: *netconf/netconf*.

Example of `docker ps` command result, after the NTS Manager was started:

```
7ff723b7f794        ntsim_manager:latest   "sh -c '/usr/bin/sup…"   5 days ago          Up 5 days           172.17.0.1:8300->830/tcp       NTS_Manager
```

### Using the NTST Manager

When the NTS Manager is started, its default configuration looks like this:

```xml
<simulator-config xmlns="urn:onf:params:xml:ns:yang:network-topology-simulator">
	<simulated-devices>0</simulated-devices>
	<mounted-devices>0</mounted-devices>
	<notification-config>
		<fault-notification-delay-period>0</fault-notification-delay-period>
		<ves-heartbeat-period>0</ves-heartbeat-period>
		<is-netconf-available>true</is-netconf-available>
		<is-ves-available>true</is-ves-available>
	</notification-config>
	<controller-details>
		<controller-ip>172.17.0.1</controller-ip>
		<controller-port>8181</controller-port>
		<controller-username>admin</controller-username>
		<controller-password>admin</controller-password>
	</controller-details>
	<ves-endpoint-details>
		<ves-endpoint-ip>172.17.0.1</ves-endpoint-ip>
		<ves-endpoint-port>30007</ves-endpoint-port>
		<ves-endpoint-auth-method>no-auth</ves-endpoint-auth-method>
		<ves-registration>false</ves-registration>
	</ves-endpoint-details>
</simulator-config>
```

This configuration can be altered by connecting to the NTS Manager with a NETCONF Client.

### Starting a simulated device

Example of starting **one** simulated device:

If the leaf `<simulated-devices>1</simulated-devices>` will be set to a value of **1**, the NTS Manager will start a new docker container. We can verify that this was successfull by running the `docker ps` command. The results will look like this:

```
c18eb7a362f5        ntsim_oran             "sh -c '/usr/bin/sup…"   4 days ago          Up 4 days           172.17.0.1:50000->830/tcp, 172.17.0.1:50001->831/tcp, 172.17.0.1:50002->832/tcp, 172.17.0.1:50003->833/tcp, 172.17.0.1:50004->834/tcp, 172.17.0.1:50005->835/tcp, 172.17.0.1:50006->836/tcp, 172.17.0.1:50007->837/tcp, 172.17.0.1:50008->838/tcp, 172.17.0.1:50009->839/tcp   reverent_bhabha
```

We can see that the simulated device has 10 NETCONF Endpoints listening for connections. The first 7 (50000 to 50006) are SSH connections, while the last 3 (50007 to 50009) are TLS connections.


## Troubleshooting

### No simulated devices are starting

If, after setting the leaf `<simulated-devices>1</simulated-devices>` to a value greater that 0, no new containers are created, please make sure that the image name specified in the **MODELS_IMAGE** environment variable when starting the NTS Manager is present in the host. You can verify that using the `docker images` command.

Example of a result of such a command:

```
ntsim_oran       latest           57b065de4458     4 days ago     785MB
```

This means that `MODELS_IMAGE: "ntsim_oran:latest"` can be used as an environment variable when starting the NTS Manager.

## Known limitations

There are some known limitations with regards to the OpenROADM information models:
* YANG modules that are not implemented:
    * org-openroadm-flexogroup-capability.yang
    * org-openroadm-ipv4-unicast-routing.yang
    * org-openroadm-ipv6-unicast-routing.yang
    * org-openroadm-lldp.yang
    * org-openroadm-ospf.yang
    * org-openroadm-routing.yang