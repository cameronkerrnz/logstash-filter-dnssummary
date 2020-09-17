#!/bin/bash

curl -s -XGET "localhost:9600/_node/stats/pipelines?pretty" \
    | jq ".pipelines.main.plugins.filters[] | select(.id==\"dnssummary0\") | .events | ( .duration_in_millis / .out )"
