# R3c0n
### V-12.23.2021
simple toolset for automating recon and scanning tasks.
This project is on early stages of development.

-------------------------------------------------------------

## Running R3c0n :
It is recommended to run it on a kali-linux machine , cause there are some tools that are automated in these scripts which are pre-installed on kali.
Or if you want to run it on other OS's make sure you install all requirements first.
**Command to run R3c0n:** 
as you know first git clone it 
`git clone https://github.com/bijan53c/R3c0n
cd R3c0n`
then
`sudo sh r3c0n.sh <Target domain>`

## Dependencies :
- python3 
- python requests library
-  ' '   urllib   '  '
- ***Tools automated in this program:***
  - Gobuster
  - Whatweb
  - WafW00f
  - assetfinder 


## Making most use of R3c0n:
There are some scripts which need some keys and codes which you need to customize them.
- ***Telegram notification:*** You need to enter your telegram bot token and chat id in `telegramSimpleAPI.py` script to receive notifications via telegram , everytime a scan is done. This script will be updated for more features.
- ***Checking what websites are built with:*** For thise section we use *wapplyzer* api. So you should use your own api key to use this feature. You can edit `wappy.py` to enter your own API key.

## Built in tools and scripts
- bing_dork.py > uses bing search engine to dork for related urls and subdomains
- wappy.py     > uses wapplyzer api to find technologies used in target website
- there are some other scripts in `scanners` directory which are not automated yet.


## Features to add (To-do):
- [ ] Adding vulnerability scanners
- [x] Making wappy.py ready and automated
- [ ] Clean output file format
- [ ] list input for giving list of target domains to R3c0n
