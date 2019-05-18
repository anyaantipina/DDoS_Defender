# !/bin/bash
string="10.0.0."
start=0
end=0
gap1=0
gap2=0
if [[ $1 = 1 ]]
then
	gap1=3
else
	if [[ $1 = 3 ]]
	then
		gap1=1
		gap2=4
	else
		if [[ $1 = 4 ]]
		then
			gap1=8
		else
			if [[ $1 = 8 ]]
			then
				gap1=4
			fi
		fi
	fi
fi
if [[ $1 > 2 ]] && [[ $1 < 8 ]]
then
	let "start = $1 % 8 + 1"
        let "end = 7 - ( 8 - start + 1 )"
else
	let "start = ( $1 + 1 ) % 8"
	let "end = start + 6"
fi

	let "index = start"
	echo "start"$start
	echo "end"$end
	echo "index"$index
	if [[ $start < $end ]]
	then
		while [[ $index < $end ]]
		do
if [[ $index != $gap1 ]] && [[ $index != $gap2 ]]
then
			ip=$string$index
			ping $ip -w 10
fi
			let "index=index+1"
		done
	else
		let "index = 1"
		while [[ $index < $end ]]
		do
if [[ $index != $gap1 ]] && [[ $index != $gap2 ]]
then
 	               ip=$string$index
                       ping $ip -w 10
fi
                       let "index=index+1"
                done
		let "index = start"
		while [[ $index < 9 ]]
                do
if [[ $index != $gap1 ]] && [[ $index != $gap2 ]]
then
                        ip=$string$index
                        ping $ip -w 10
fi
                        let "index=index+1"
                done
	fi	
sleep 10
if [[ $1 = 1 ]]
then
	ping 10.0.0.3  
else
	if [[ $1 = 3 ]]
	then
		ping 10.0.0.4
	else
		if [[ $1 = 4 ]]
		then
			ping 10.0.0.8
		fi
	fi
fi

