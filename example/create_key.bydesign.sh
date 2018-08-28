#!/bin/bash

cat <<EOF

Generating a new test key and certificate.  To change the defaults offered
by openssl, edit your openssl.cnf, such as /etc/ssl/openssl.cnf

EOF

openssl genrsa -out server.key 2048
chmod 600 server.key
openssl req -x509 -new -nodes -extensions v3_ca -key server.key -days 3650 -out server.csr -sha1

cat <<EOH

Now to enable these new keys, do:

  cp server.key idp2/pki/mykey.pem
  cp server.csr idp2/pki/mycert.pem

  cp server.key sp-wsgi/pki/mykey.pem
  cp server.csr sp-wsgi/pki/mycert.pem

To create idp.xml, do:
  cd /to/idp2/folder
  ../../tools/make_metadata.py idp_conf.py > idp.xml
EOH
