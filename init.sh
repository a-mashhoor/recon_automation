#!/usr/bin/env zsh 
# this is the initialization script it will install all the tools used by the script on a kali machine itself so you dont have to!

echo "This init script is designed for a kali linux machine"
echo "you must run this script under root user privilages!"

os=$( hostnamectl  | grep "Operating System:"  | awk '{print $3 $4 $5}')
if [[ "$os" == "KaliGNU/LinuxRolling" ]]; then 
    echo "your machine is kali scripts will run"
else 
    echo "not a kali machine"
    exit 1
fi

echo adding path to PATH in .zshrc 
if [[ ! -d  ~/.local/bin ]]; then   
    mkdir -p ~/.local/bin 
fi 
echo "export PATH=$PATH:~/.local/bin" >> ~/.zshrc 

apt install golang git figlet pcregrep curl wafw00f jq sed assetfinder subfinder dnsmap ffuf \
    httprobe waybackpy amass dnsutils bind9-host nmap whois gobuster zip unzip seclists  

while pgrep apt do; 
    sleep 1
done 


wget https://github.com/projectdiscovery/urlfinder/releases/download/v0.0.1/urlfinder_0.0.1_linux_amd64.zip && unzip urlfinder_0.0.1_linux_amd64.zip 
rm LICENSE.md README.md urlfinder_0.0.1_linux_amd64.zip && mv urlfinder -t  ~/.local/bin 

wget https://github.com/projectdiscovery/katana/releases/download/v1.1.1/katana_1.1.1_linux_amd64.zip && unzip katana_1.1.1_linux_amd64.zip
rm LICENSE.md README.md katana_1.1.1_linux_amd64.zip && mv katana  -t ~/.local/bin 

git clone https://github.com/tomnomnom/hacks.git hacks 
go build -o inscope hacks/inscope/main.go && mv inscope -t ~/.local/bin 
go build -o fff hacks/fff/main.go && mv fff -t ~/.local/bin 
rm -rf hacks/

git clone https://github.com/PentestPad/subzy.git subzyy
go build -o subzy subzyy/main.go && mv subzy -t ~/.local/bin && rm -rf subzyy/ 
