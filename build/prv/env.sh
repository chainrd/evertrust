#!/bin/sh

export GOSUMDB=off
set -e

if [ ! -f "build/prv/env.sh" ]; then
    echo "$0 must be run from the root of the repository."
    exit 2
fi

cd "build/prv/"

exec "$@"