#!/bin/bash

# Usage
function print_usage {
    echo "USAGE: ${0} [--prefix=<install-prefix>] [--keep-config]"
}

# Parse arguments

PREFIX="/usr"
KEEP_CONFIG=0

if [ ! -z "${DSTDIR}" ]; then
    PREFIX="${DSTDIR}"
fi

for i in "$@"
do
case ${i} in
    --prefix=*)
    PREFIX="${i#*=}"
    shift # past argument=value
    ;;
    --keep-config)
    KEEP_CONFIG=1
    shift # past argument with no value
    ;;
    -h|--help)
    print_usage
    exit 0
    ;;
    --prefix)
    echo "Option --prefix requires argument."
    print_usage
    exit 1
    ;;
    *)
    echo "Unknown option ${i}"
    print_usage
    exit 1
    ;;
esac
done

# Check arguments
if [ ! -d "${PREFIX}" ] ; then
    echo "Prefix directory \"${PREFIX}\" does not exists."
    print_usage
    exit 1
fi

echo "Delete binaries..."
find "${PREFIX}" -name "virgil" -type f -exec rm {} \; > /dev/null 2>&1

echo "Delete docs..."
find "${PREFIX}" -name "virgil*.[1-9]" -type f -exec rm {} \; > /dev/null 2>&1

if [ "${KEEP_CONFIG}" -eq "0" ] ; then
    echo "Delete configurations and logs..."
    rm -fr ~/.virgil > /dev/null 2>&1
fi
