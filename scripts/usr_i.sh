# !/bin/bash
string="10.0.0."
start=0
end=0

if [[ $1 > 3 ]] && [[ $1 < 8 ]]
then
	let "start = $1 % 8 + 1"
        let "end = 6 - ( 8 - start + 1 )"
else
	let "start = ( $1 + 1 ) % 8"
	let "end = start + 5"
fi

let "index = start"
echo "start"$start
echo "end"$end
echo "index"$index
if [[ $start < $end ]]
then
        while [[ $index < $end ]]
        do
                ip=$string$index
                ping $ip -w 10
                let "index=index+1"
        done
else
        let "index = 1"
        while [[ $index < $end ]]
        do
                ip=$string$index
                ping $ip -w 10
                let "index=index+1"
        done
        let "index = start"
        while [[ $index < 9 ]]
        do
                ip=$string$index
                ping $ip -w 10
                let "index=index+1"
        done
fi

if [[ $1 = 3 ]]
then
	iperf3 -s
else
	if [[ $1 = 6 ]]
	then
		iperf3 -s
	fi
fi

sleep 5
if [[ $1 = 1 ]]
then
	iperf3 -c 10.0.0.3 -t 300
else
	if [[ $1 = 4 ]]
	then
		iperf3 -c 10.0.0.6 -t 300
	fi
fi
