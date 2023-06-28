#!/bin/bash

PIDS=`ps -aux | grep ebpf | awk '{print $2}'`
for PID in $PIDS;
do
    kill -9 $PID
done
