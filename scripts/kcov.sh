#!/bin/bash

# $1 is the binary to run, all other parameters after are optional and passed to the binary

KCOV=${KCOV_BINARY:?}

if ! ${KCOV:?} --version &> /dev/null ; then echo "${KCOV} executable not found" ; exit 1 ; fi
if ! [ -d ${KCOV_TARGET_DIRECTORY:?} ] ; then echo "target dir does not exist: ${KCOV_TARGET_DIRECTORY:?}"; exit 1 ; fi

# always place coverage reports in a unique directory for each binary...

COVERAGE_OUTPUT_DIR=${KCOV_TARGET_DIRECTORY:?}/$(basename ${1:?})
mkdir -p ${COVERAGE_OUTPUT_DIR:?}

# run kcov
KCOV_CALL="${KCOV:?} --include-pattern=${KCOV_INCLUDE_PATTERN:?} ${KCOV_EXCLUDE_LINE_ARG} ${KCOV_EXCLUDE_REGION_ARG} ${COVERAGE_OUTPUT_DIR:?} $@"

echo ${KCOV_CALL:?}
exec ${KCOV_CALL:?}