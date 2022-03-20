#!/bin/bash

if [ -z "$1" ]
then
        echo "Usage: sudo sh r3c0n.sh <Target URL>"
        exit 1
fi

# ##
# Color Variables
##
green='\e[32m'
blue='\e[34m'
clear='\e[0m'
##

##
# Color Functions
##
ColorGreen(){
 echo $green$1$clear
}
ColorBlue(){
 echo $blue$1$clear
}
##
echo $(ColorBlue '< --- R3c0n_v.03.20.2022 --- >\n')
echo "$1" > targeturl.txt
echo "$1" > scanners/targeturl.txt

echo $(ColorGreen '\n running whatweb...\n')
echo "------ WhatWeb ------\n" > OutputFiles/$1'.md'
whatweb $1 >> OutputFiles/$1'.md'


echo $(ColorGreen '\n running wafw00f...\n')
echo "\n------ WafW00f ------\n" >> OutputFiles/$1'.md'
wafw00f -a $1 >> OutputFiles/$1'.md'

echo $(ColorGreen '\n running NMAP -A ... \n')
echo "\n ------ NMAP ------ \n" >> OutputFiles/$1'.md'
nmap -a $1 >> OutputFiles/$1'.md'

echo $(ColorGreen '\n running assetfinder...\n')
echo "------ Assets (using assetfinder) ------\n" >> OutputFiles/$1'.md'
assetfinder $1 >> OutputFiles/$1'.md'

echo $(ColorGreen 'running nikto...\n')
echo "\n------ Nikto ------\n" >> OutputFiles/$1'.md'
nikto -h $1 >> OutputFiles/$1'.md'

echo $(ColorGreen '\n running GoBuster...\n')
echo "\n------ GoBuster ------\n" >> OutputFiles/$1'.md'
gobuster -u $1 -w Wordlists/SECLISTcommon.txt -fw >> OutputFiles/$1'.md'



echo $(ColorBlue '\n running python scripts("Scanners!!")...\n')
echo "\n <========== PY-Scripts ==========>\n" >> OutputFiles/$1'.md'

echo $(ColorGreen 'Dorking using bing search engine...\n')
echo "\n------ Bing_Dorks_result ------\n" >> OutputFiles/$1'.md'
python3 ./scanners/bing_dork.py
cat bingDORK_Result.txt >> OutputFiles/$1'.md'

echo $(ColorGreen 'Running wappy.py (wapplyzer api) ...\n')
echo "\n------ wappy.py _(wapplyzer API)_  ------\n" >> OutputFiles/$1'.md'
python3 ./scanners/wappy.py
cat wappyresult.txt >> OutputFiles/$1'.md'


echo '\n##### All Done #####\n'
echo $(ColorBlue "\nResults have been saved in "$1'.md , in "OutputFiles/" directory . \n')
#sending simple message to telegram
python3 telegramSimpleAPI.py
exit 1
