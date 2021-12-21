#!/bin/bash

if [ -z "$1" ]
then
        echo "Usage: sudo sh A-R.sh <Target URL>"
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
echo $(ColorBlue '< --- A-R-v.12.21.2021 --- >\n')
echo "$1" > targeturl.txt
echo "$1" > scanners/targeturl.txt

echo $(ColorGreen 'running whatweb...\n')
echo "------ WhatWeb ------\n" > OutputFiles/$1'.md'
whatweb $1 >> OutputFiles/$1'.md'


echo $(ColorGreen 'running wafw00f...\n')
echo "\n------ WafW00f ------\n" >> OutputFiles/$1'.md'
wafw00f -a $1 >> OutputFiles/$1'.md'

#echo $(ColorGreen 'running nikto...\n')
#echo "\n------ Nikto ------\n" >> OutputFiles/$1'.md'
#nikto -host $1 -timeout 5 >> OutputFiles/$1'.md'

echo $(ColorGreen 'running GoBuster...\n')
echo "\n------ GoBuster ------\n" >> OutputFiles/$1'.md'
gobuster dir --url $1 -w Wordlists/SECLISTcommon.txt >> OutputFiles/$1'.md'



echo $(ColorBlue 'running python scripts("Scanners!!")...\n')
echo "\n <========== PY-Scripts ==========>\n" >> OutputFiles/$1'.md'

echo $(ColorGreen 'Dorking using bing search engine...\n')
echo "\n------ Bing_Dorks_result ------\n" >> OutputFiles/$1'.md'
python3 ./scanners/bing_dork.py
cat bingDORK_Result.txt >> OutputFiles/$1'.md'

#echo $(ColorGreen '\n trying XSS on the target URL ...\n')
#echo $(ColorGreen '\n automated XSS is not running on discoverd directories yet!\n It will happen in updates.')
#echo "\n------ XSS ------\n" >> OutputFiles/$1'.md'
#python3 ./scanners/xss.py >> OutputFiles/$1'.md'


echo '\n##### All Done #####\n'
echo $(ColorBlue "\nResults have been saved in "$1'.md , in "OutputFiles/" directory . \n')
#sending simple message to telegram
python3 telegramSimpleAPI.py
exit 1
