# !/bin/bash
string="10.0.0."
start=$1
end=$1
let "end = end + 10"

let "index = start"
echo "start"$start
echo "end"$end
echo "index"$index

if [[ $1 > 1 ]]
then
    while [[ $index < $end ]]
    do
        ip=$string$index
        ping $ip -w 3
        let "index=index+1"
    done
fi
if [[ $1 == 1 ]]
then
    echo "ip"$1
    let "index = 2"
    while [[ $index < 9 ]]
    do
        ip=$string$index
        ping $ip -w 3
        let "index=index+1"
    done
    ping 10.0.0.9 -w 3
fi
if [[ $1 == 90 ]]
then
    echo "ip"$1
    let "index = 1"
    while [[ $index < 9 ]]
    do
        ip=$string"9"$index
        ping $ip -w 3
        let "index=index+1"
    done
    ping 10.0.0.99 -w 3
fi
