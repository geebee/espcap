#!/usr/bin/env bash

# Run this script before you do anything else with espcap
# to make sure all dates are properly mapped to date types
# in Elasticsearch.

if [[ $# -ne 2 ]] ; then
    echo "usage: template.sh node template"
    exit
fi

curl -XPUT 'http://'$1'/_template/packets-template' --data @$2

echo
