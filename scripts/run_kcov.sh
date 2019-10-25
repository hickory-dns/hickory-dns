#!/bin/bash -e

set -x

# THIS SCRIPT ASSUMES TESTS HAVE ALREADY BEEN BUILT
# *WARING* it is destructive and installs kcov via sudo!

trust_dns_dir=$(dirname $0)/..
cd ${trust_dns_dir:?}

case $(uname) in
  Darwin) exit 0;;
  *)      KCOV=true;;
esac

# don't run on nightly or beta
rustc --version | grep beta && exit 0;
rustc --version | grep nightly && exit 0;

rm -rf kcov-master master.tar.gz*

# install kcov
# sudo apt-get install libcurl4-openssl-dev libelf-dev libdw-dev
sudo apt-get update --yes
sudo apt-get install --yes cmake libcurl4-openssl-dev libelf-dev libdw-dev
wget https://github.com/SimonKagstrom/kcov/archive/master.tar.gz
tar xzf master.tar.gz
mkdir kcov-master/build
cd kcov-master/build
cmake ..
make
sudo make install
cd ../..

PROJECT=${PWD}
WORK_DIR=${PROJECT:?}/crates/server
KCOV_TARGET=${PROJECT:?}/target
TEST_PATH=${PROJECT:?}/target/debug

# run kcov on all tests, rerunning all tests with coverage report
mkdir -p ${KCOV_TARGET:?}

# needed to tell some config tests where the server root directory is
export TDNS_SERVER_SRC_ROOT=${PROJECT:?}/bin
export COVERALLS_PARALLEL=true

SRC_PATHS=\
${PROJECT:?}/crates/client/src,\
${PROJECT:?}/crates/native-tls/src,\
${PROJECT:?}/crates/openssl/src,\
${PROJECT:?}/crates/proto/src,\
${PROJECT:?}/crates/https/src,\
${PROJECT:?}/crates/resolver/src,\
${PROJECT:?}/crates/rustls/src,\
${PROJECT:?}/crates/server/src,\
${PROJECT:?}/bin/src

EXCLUDE_PATHS=\
${PROJECT:?}/crates/client/src/error,\
${PROJECT:?}/crates/proto/src/error.rs,\
${PROJECT:?}/crates/server/src/error,\
${PROJECT:?}/tests/compatibility-tests/src/lib.rs,\
${PROJECT:?}/tests/integration-tests/src/lib.rs

pushd ${WORK_DIR:?}
for i in ${TEST_PATH:?}/trust_dns*-* ${TEST_PATH:?}/*_tests-* ; do
  if [ -f $i ] && [ -x $i ]; then
    # submit the report... what's the executable since there are many?
    echo "----> executing kcov on $i"
    kcov --exclude-pattern=${PROJECT:?}/.cargo \
         --include-path=${SRC_PATHS} \
         --exclude-path=${EXCLUDE_PATHS} \
         ${KCOV_TARGET:?}/kcov-$(basename $i) $i

    let test_count='test_count+1'
    
    # this only works for a single test run upload
    last_test=$i
  fi
done
popd

echo "----> ran $test_count test(s)"

echo "----> uploading to codecov.io"
bash <(curl -s https://codecov.io/bash) -c -F ${NAME}
echo "----> coverage reports done"