#! /bin/bash

sleep 5

openssl genrsa -out melacon.server.key 2048

openssl req -new -sha256 -key melacon.server.key -subj "/C=US/ST=CA/O=MeLaCon, Inc./CN=melacon.com" -out melacon.server.csr
openssl x509 -req -in melacon.server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out melacon.server.crt -days 500 -sha256
rm melacon.server.csr

MELACON_SERVER_KEY="$(sed '1d;$d' melacon.server.key)"

echo '<action xmlns="urn:ietf:params:xml:ns:yang:1"><keystore xmlns="urn:ietf:params:xml:ns:yang:ietf-keystore"><private-keys><load-private-key><name>melacon_server_key</name>' >> load_private_key.xml
echo '<private-key>'"$MELACON_SERVER_KEY"'</private-key></load-private-key></private-keys></keystore></action>' >> load_private_key.xml

netopeer2-cli <<END
auth pref publickey 1000
auth keys add /home/netconf/.ssh/id_dsa.pub /home/netconf/.ssh/id_dsa
connect --login netconf
user-rpc --content=load_private_key.xml
disconnect
END

rm load_private_key.xml

MELACON_CERT="$(sed '1d;$d' melacon.server.crt)"
CA_CERT="$(sed '1d;$d' ca.pem)"

echo '<keystore xmlns="urn:ietf:params:xml:ns:yang:ietf-keystore"><private-keys><private-key><name>melacon_server_key</name><certificate-chains><certificate-chain><name>melacon_server_cert</name>' >> load_server_certs.xml
echo '<certificate>'"$MELACON_CERT"'</certificate></certificate-chain></certificate-chains></private-key></private-keys><trusted-certificates><name>trusted_ca_list</name><trusted-certificate><name>ca</name>' >> load_server_certs.xml
echo '<certificate>'"$CA_CERT"'</certificate></trusted-certificate></trusted-certificates></keystore>' >> load_server_certs.xml

sysrepocfg --merge=load_server_certs.xml --format=xml ietf-keystore
rm load_server_certs.xml

echo '<netconf-server xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-server"><listen>' >> tls_endpoints.xml
echo '<endpoint><name>MNG_TLS_1</name><tls><address>0.0.0.0</address><port>837</port><certificates><certificate><name>melacon_server_cert</name></certificate></certificates><client-auth><trusted-ca-certs>trusted_ca_list</trusted-ca-certs><cert-maps><cert-to-name><id>1</id><fingerprint>02:E9:38:1F:F6:8B:62:DE:0A:0B:C5:03:81:A8:03:49:A0:00:7F:8B:F3</fingerprint><map-type xmlns:x509c2n="urn:ietf:params:xml:ns:yang:ietf-x509-cert-to-name">x509c2n:specified</map-type><name>netconf</name></cert-to-name></cert-maps></client-auth></tls></endpoint>' >> tls_endpoints.xml
echo '<endpoint><name>MNG_TLS_2</name><tls><address>0.0.0.0</address><port>838</port><certificates><certificate><name>melacon_server_cert</name></certificate></certificates><client-auth><trusted-ca-certs>trusted_ca_list</trusted-ca-certs><cert-maps><cert-to-name><id>1</id><fingerprint>02:E9:38:1F:F6:8B:62:DE:0A:0B:C5:03:81:A8:03:49:A0:00:7F:8B:F3</fingerprint><map-type xmlns:x509c2n="urn:ietf:params:xml:ns:yang:ietf-x509-cert-to-name">x509c2n:specified</map-type><name>netconf</name></cert-to-name></cert-maps></client-auth></tls></endpoint>' >> tls_endpoints.xml
echo '<endpoint><name>MNG_TLS_3</name><tls><address>0.0.0.0</address><port>839</port><certificates><certificate><name>melacon_server_cert</name></certificate></certificates><client-auth><trusted-ca-certs>trusted_ca_list</trusted-ca-certs><cert-maps><cert-to-name><id>1</id><fingerprint>02:E9:38:1F:F6:8B:62:DE:0A:0B:C5:03:81:A8:03:49:A0:00:7F:8B:F3</fingerprint><map-type xmlns:x509c2n="urn:ietf:params:xml:ns:yang:ietf-x509-cert-to-name">x509c2n:specified</map-type><name>netconf</name></cert-to-name></cert-maps></client-auth></tls></endpoint>' >> tls_endpoints.xml
echo '</listen></netconf-server>' >> tls_endpoints.xml

sysrepocfg --merge=tls_endpoints.xml --format=xml ietf-netconf-server
rm tls_endpoints.xml

echo 'Done'
exit 0