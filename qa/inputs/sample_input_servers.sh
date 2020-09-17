#!/bin/bash
#
# Produce an infinite loop of inputs that are
# representative of a production workload based
# on servers communicating through a proxy.
#
# We do this my taking lines of (input,count) pairs,
# making 'count' repeats of 'input', then shuffling
# all those lines. We then repeat the process
# ad-infinitum.
#
# This is run within the QA container.

trap 'exit 0' SIGTERM

while true
do
    awk '{ for (i=0; i<$2; i++) { print $1 } }' \
        sample_input_servers.log.in | shuf
done </dev/null