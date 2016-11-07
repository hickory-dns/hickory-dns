#!/bin/bash -e

trust_dns_dir=$(dirname $0)/..
cd ${trust_dns_dir:?}

case $(uname) in
  Darwin) exit 0;;
  *)      KCOV=true;;
esac

# don't run on nightly or beta
rustc --version | grep beta && exit 0;
rustc --version | grep nightly && exit 0;

# install kcov
sudo apt-get install libcurl4-openssl-dev libelf-dev libdw-dev
wget https://github.com/SimonKagstrom/kcov/archive/master.tar.gz
tar xzf master.tar.gz
mkdir kcov-master/build
cd kcov-master/build
cmake ..
make
sudo make install
cd ${trust_dns_dir}

# run kcov on all tests, rerunning all tests with coverage report
mkdir -p target

SRC_PATHS=client/src,server/src
EXCLUDE_PATHS=client/src/error,server/src/error

for target/debug/trust_dns*-* target/debug/*_tests-* ; do
  if [ -f $i ] && [ -x $i ]; then
    kcov --collect-only target/kcov $i
  fi
done

# submit the report... what's the executable since there are many?
kcov --report-only \
     --coveralls-id=$TRAVIS_JOB_ID \
     --exclude-pattern=/.cargo \
     --include-paths=${SRC_PATHS} \
     --exclude-paths=${} \
     target/kcov client/target/debug/trust_dns-*
