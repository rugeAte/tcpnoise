#! /bin/bash
###TCP NOISE###
# Lee Clout 2016
# Version 4.03a

# IP/Port pair generator
# Designed to generate a list of ip addresses and ports, whilst minimising repetition within a single destination network
# For every port (1~65536) #This is currently broken andd offset by +1 # select a single host in a unique class B /16 sized network
# not sure if will bother about UDP ports
# Besides a fun project crossing bash,php,sql,html and creating custom checksums using modulus to authenticate the base16 packet.
# Essentially this script just slowly, unobtrusively scans the entire IP4 internet, thus creating meaningless log files for Telco's complying with AU data retention laws.
# They say they only log the outside of the envelope, so we send empty envelopes to every address out there.  This script could run for months before hitting the same host/port pair twice
# The net gain is we together use this noise to build a coherent picture of services on the internet, as in regardless of who is viewing our log files we get some collaborative cool data!


##### TIPS N TRICKS #####
# The dostuff fuunction is where the "external" commands happen, more stuff coming soon
# The parsenc function reacts to the various netcat outputs, the above dostuff function is triggered here. You can comment in and out the dostuff command to choose which packets to send
# a reverse IP lookup using the program host with the variable $host ...turn this off/comment it out to speed things up... soon to be deprecated for server side solution... fingers crossed
# a Netcat command with options Verbose, Numerical (don't resolve numbers), Zero I/O mode, and wait 2 seconds to timeout
# netcat uses the $host and $port variable, you could replace the port variable with 80 or something to only scan random hosts and always use same port, examples included
# lots of cool variables to use host,port,result,resultcode,hexpack,chksum

# Version 3.00 added seed memory, haven't implemented input validation yet
# Version 3.01 added changelog
# Version 3.02 added logfile by tee'ing output from function call "itoa" -a to append
# Version 3.03 added tips'n'tricks, fixed bug with writing of new seed, added search function to display any open ports found repeatedly, thinking about name change ?tcpnoise?
# Version 4.00 interfacing with webserver and potentially twitter via piping nc output to new function, said function also parses results so they can be selectively acted upon.
# Version 4.01  Implemented checksum for packet both client and server side
#               Made port 80 scanning available by uncommenting line
#               Restored local logging to file in same raw format (all variables for host and port are available now so easy to format output to requirement
#               Various security and filtering server side
# Version 4.02  Check if tcpnoise directory exists before trying to create it (avoids warning upon execution)
#               Update Notes
# Version 4.03	Fixed port 80 on second scan
#		Added twidge functionality on successful connecions, via dosuccess function

# need to fix match problem with /8 network jumps trialling new division points, having only 240(239) options in octet A makes the rollover ugly.
# the worst thing is 240 is a byte minus 5 LEAST! significant bits, so ya can't just draw a line in the bits.  maybe I should be adding LSB and subtracting MSB??
# note for above 240 is wrong! avoid class d space too

#####################################################################################################
# Check if subdirectory exists, create it if it doesn't

[ ! -d "tcpnoise/" ] && mkdir tcpnoise

#####################################################################################################
# The seedfile is essentially a counter, so if you close the script it'll pick up where you left off
# Sometimes adding 129k to the initial seed will give you more inital hits but this is mainly due to devices on x.x.x.1 being routers or inrastructure devices


seedfile=tcpnoise.seed
if [ -f $seedfile ];
then
        echo "reading $seedfile for start seed"
else
        echo "Cannot locate counter.seed will create random seed"
        x=$(($(($RANDOM%239))*1099511627776))
        x=$[$x+65536]
        echo "$x" > tcpnoise.seed
fi

read x < tcpnoise.seed
echo "Random Start Seed is $x"

#####################################################################################################
# Creates a checksum of the 21 Hexadecimal Packet before transmission to the server
# The server includes a similar function to check the integrity of the data

function crcgen
{
sum=0
for hd in $(grep -o . <<< $@); do
        sum=$(($sum + 0x$hd))
done

chksum=$(printf "%01X" $(( $sum % 16 )))
}


#####################################################################################################
# This is where external things happen, currently curl is used for web upload and data is sent to local log too
# lots of handy variables to use if needed

function dostuff
{
#curl http://subethernet.net/tcpnoise/add.php?packet=$hexpack$chksum
echo $result >> tcpnoise/$host.log
}


#####################################################################################################
# same as above dostuff, though this function is only triggered on succesful connections

function dosuccess
{
echo "$host responded on $port"
echo "I found it at IKEA"
echo "Successful $host $port"
echo -ne '\007'
}


#####################################################################################################
# This function reads the netcat output and reacts accordingly, it also parses the data into hex for transmission
# Activate dostuff for the states you wish to do stuff for!


function parsenc
{
if [[ $@ == *"timed out:"* ]]; then
                resultcode=1
                hexpack=$(printf "%08X%02X%02X%02X%02X%04X%01X\n" $(date +%s) ${host//./ } $port $resultcode)
                crcgen "$hexpack"
                printf "%-10s %-15s %-5s %-2s %-20s %22s\n" $(date +%s) $host $port $resultcode "(timed out)" $hexpack$chksum
#               dostuff
        elif [[ $@ == *"Connection refused"* ]]; then
                resultcode=2
                hexpack=$(printf "%08X%02X%02X%02X%02X%04X%01X\n" $(date +%s) ${host//./ } $port $resultcode)
                crcgen "$hexpack"
                printf "%-10s %-15s %-5s %-2s %-20s %22s\n" $(date +%s) $host $port $resultcode "(Connection Refused)" $hexpack$chksum
                dostuff
        elif [[ $@ == *"Network is unreachable"* ]]; then
                resultcode=4
                hexpack=$(printf "%08X%02X%02X%02X%02X%04X%01X\n" $(date +%s) ${host//./ } $port $resultcode)
                crcgen "$hexpack"
                printf "%-10s %-15s %-5s %-2s %-20s %22s\n" $(date +%s) $host $port $resultcode "(Network Unreachable)" $hexpack$chksum
                dostuff
        elif [[ $1 == *"No route to host"* ]]; then
                resultcode=8
                hexpack=$(printf "%08X%02X%02X%02X%02X%04X%01X\n" $(date +%s) ${host//./ } $port $resultcode)
                crcgen "$hexpack"
                printf "%-10s %-15s %-5s %-2s %-20s %22s\n" $(date +%s) $host $port $resultcode "(No Route to Host)" $hexpack$chksum
                dostuff
        elif [[ $@ == *"succeeded!" ]]; then
                resultcode=15
                hexpack=$(printf "%08X%02X%02X%02X%02X%04X%01X\n" $(date +%s) ${host//./ } $port $resultcode)
                crcgen "$hexpack"
                printf "%-10s %-15s %-5s %-2s %-20s %22s\n" $(date +%s) $host $port $resultcode "(Successful)" $hexpack$chksum
                dostuff
		dosuccess

        fi
}

#####################################################################################################

# this function is called from loop with the x variable (a 6 byte number represented in decimal)
# it uses host to do a reverse IP lookup (beware of potential misuse due to so many lookups)
#  then uses netcat (nc) to attempt a TCP handshake
function itoa
{
#returns the dotted-decimal ascii form of an IP arg passed in integer format
host=$(($(($(($(($(($((${1}/256))/256))/256))/256))/256))%256)).$(($(($(($(($((${1}/256))/256))/256))/256))%256)).$(($(($(($((${1}/256))/256))/256))%256)).$(($(($((${1}/256))/256))%256))
port=$[$((${1}%65536))+1]

# return to stout a newline and echo the reult of above calculations
#echo ;echo $host $port 2>&1

# run the host command to do a reverse lookup on IP
# host $host 2>&1 | tee -a tcpnoise/$host.log


# run the nc command
result=$((nc -vnzw2 $host $port ) 2>&1 ); parsenc "$result"
# Uncomment below to bypass sequential ports
port=80
result=$((nc -vnzw2 $host $port ) 2>&1 ); parsenc "$result"


# update counter
echo "$x" > tcpnoise.seed
}



#####################################################################################################
## lets go.... the while loop goes infinite, it's true 0 is always less than 1

while [ "0" -lt "1" ]
do
# test if under 239.255.255.255:65536 11011111 11111111 11111111 11111111 11111111 11111111
#if [ "$x" -lt "263882790666239" ]
if [ "$x" -lt "246290604621823" ]
        then
                itoa "$x"
                # this will keep found connections at bottom of screen use open$ for pi and succeeded!$ for ubuntu
#               echo ; echo ; grep succeeded!$ tcpnoise/*
                # add one bits @ position 40,35,31,1      00000000 10000100 01000000 00000000 00000000 00000001
                x=$[$x+1136018849793]

                #testing above comment out below
                # add one bit to second octet and one LSB 00000000 00000001 00000000 00000000 00000000 00000001
                #x=$[$x+4294967297]
                # add one bit to first octet 00000001 00000000 00000000 00000000 00000000 00000000
                #x=$[$x+1099511627776]
#               sleep 0.5
        else
                # minus 11110000 00000000 00000000 00000000 00000000 00000000
                #x=$[$x-263882790666240]
                x=$[$x-246290604621824]
                # add one bit to first octet 00000001 00000000 00000000 00000000 00000000 00000000
                # this is to skip 0.0.0.0 network
                x=$[$x+1099511627776]
fi
done

#####################################################################################################


exit(0)

