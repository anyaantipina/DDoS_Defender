# !/bin/bash
ip="10.0.0."$1
mac=$2
sudo /home/anna/hyenae-0.36-1/src/hyenae -a udp -I 1 -s $mac-$ip@%% -d %-%@%% -e 10

