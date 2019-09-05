#!/bin/bash
# use testnet settings,  if you need mainnet,  use ~/.hatchcore/hatchd.pid file instead
hatch_pid=$(<~/.hatchcore/testnet3/hatchd.pid)
sudo gdb -batch -ex "source debug.gdb" hatchd ${hatch_pid}
