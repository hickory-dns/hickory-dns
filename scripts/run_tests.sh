#!/bin/bash -e

MODULES=${MODULES:-"client native-tls server"}
CLIENT_OPTIONS=${CLIENT_OPTIONS} # add in all features
OPTIONS=${OPTIONS}

trust_dns_dir=$(dirname $0)/..
cd ${trust_dns_dir:?}

for i in ${MODULES:?}; do
  pushd $i
  opts=${OPTIONS}
  if [ $i == "client" ] ; then opts="${OPTIONS} ${CLIENT_OPTIONS}" ; fi
    
  echo "executing $i: cargo test ${opts} $@"
  cargo test ${opts} $@
  popd
done
