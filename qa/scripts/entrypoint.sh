#!/bin/bash -e

# This should ONLY be run from within the container; it will
# kill all processes it can when it has received its fill of
# timing results.

echo "##############################################"
echo "### LOGSTASH PLUGIN METRIC TESTING HARNESS ###"
echo "### All processes will be terminated after ###"
echo "### after required lines of output have    ###"
echo "### been produced.                         ###"
echo "##############################################"

trap 'exit 0' SIGTERM

export LS_JAVA_OPTS="-Dls.cgroup.cpuacct.path.override=/ -Dls.cgroup.cpu.path.override=/ $LS_JAVA_OPTS"

( cd /qa/inputs; exec ./sample_input_servers.sh </dev/null ) \
    | logstash \
    | awk '
        NR  %  10000 == 0 { system("/qa/scripts/collect.sh") }
        NR >= 100000 {
            print("FINISHING");
            system("kill -TERM -1");
        }
        '
