#!/usr/bin/env zsh  

# important note: please before using this script read the README.md !!!
#
# Author Arshia Mashhoor (l0uiew)
#
# github https://github.com/l0uiew/recon_automation.git 


# importing functions! acctualy source them! 
source ./funcs.sh  

echo -e "\n\n\033[1;36m$(figlet -c -w 150  -t "The Recon Automation")"
echo -e "\033[1;37mAuthor: l0uiew\ngithub -->> https://github.com/l0uiew/recon_automation.git\033[1;32m\n\n"

# note because we are using source we must use return insead of exit the shell will close as well as the script
# of course we need a CL argument ! 
if [ "$1" = "-d" ]; then
    if [ -z "$2" ]; then
        echo -e "\033[1;32musage: -d domain.top_level_domain" > /dev/stderr
        echo "also you can add --deep at the end for intance subdomain brute force using fuff" > /dev/stderr 
        echo "usage: -d domain.top_level_domain --deep"  > /dev/stderr
        exit 1
    fi
    if [[ "$3" ]] && [[ "$3" != "--deep" ]]; then
        echo "wrong swith last swith either can be --deep or nothing" > /dev/stderr
        exit 1
    fi
    domain="$2"
else
    echo "\033[1;32musage: -d domain.top_level_domain" > /dev/stderr
    echo "also you can add --deep at the end for intance subdomain brute force using fuff" > /dev/stderr
    echo "usage: -d domain.top_level_domain --deep"> /dev/stderr
    exit 1
fi

# Cheking for internet connection
for interface in $(ls /sys/class/net/ | grep -v lo | grep -v docker0); do
    if [[ $(cat /sys/class/net/$interface/carrier) = 1 ]]; then OnLine=1; break; fi
done
if ! [[ $OnLine ]] && ! ping -c1 1.1.1.1 &>/dev/null; then echo "\033[1;32mYou are not online check your connection" > /dev/stderr; exit; fi

# If website is down tell the user and exit 
if ping -c2 "$domain" &>/dev/null ;then 
    echo -e "\033[1;32mwebsite is up proceeding..." 
else 
    echo -e "\033[1;32mwebsite is down or domain is incorrect exiting" > /dev/stderr
    exit 1 
fi

# cheking if websitse is not have a valid certification! 
if ! curl -s -I "https://$domain:443/" &>/dev/null ; then
    read -t 10 -qs "yn?the certification of target might not be valid are sure to want to proceed? "
    if ! user_agr "$yn"; then exit 1; fi    
fi

# for using inscope tool by tomnomnom we must have .scope file making sure that exist and contains valid information
echo "cheking for .scope file"

if [[ ! -f ./.scope ]]; then  
    echo -e "no scope file found! \n\nGenerate .scope file to preceede....
    \b\b\b\bnote that if the scope file must least contain 1 url or domain with regex for inscope tool! with or without wild card" > /dev/stderr ;
    read -t 10 -qs "yn?do you want to create one? y/n: "
    if ! user_agr "$yn"; then exit 1; fi 

elif ! grep -q . .scope; then
    echo ".scope file does not contain any lines! exiting" > /dev/stderr
    read -t 10 -qs "yn?do want to edit it? y/n: "
    if ! user_agr "$yn"; then exit 1; fi 
else
    echo -e "\n.scope file found. cheking it validation";
    fi    

    sleep 1
    if [[ ! -f ./.scope ]]; then
        echo -e "\nsomething went worng file does not exist! or it contains nothing"  > /dev/stderr
        exit 1
    elif ! grep -q . ./.scope ; then
        echo -e "\n.scope file is empty exiting the script" > /dev/stderr
        exit 1
    else
        if grep -q -Eo "^(https|http|\.|\*|\.|\^)[a-zA-Z0-9./*?=_%:-].*(.\$)" .scope || grep -q -Eo "([a-zA-Z]*\..*){1,}$" .scope ; then 
            echo -e "\n.scope file contains valid like url preciding...\n scope file contains:\n"
            echo -e "\033[0;33m$(cat .scope)\033[1;32m\n" 
        else
            echo -e "\n\033[1;33m.scope file does not contain valid like url exiting\033[1;32m" > /dev/stderr
            exit 1
        fi
    fi  

#parent result directory !
mkdir -p results

echo -e "Staring the Recon..."

echo -e "cheking for WAF...\n"
if [[ ! -f results/waf ]]; then 
    wafw00f "$domain" -a -o results/waf &>/dev/null &&  
        echo -e "\033[0;32m \bThe web application is behinde\033[0;31m $(cat results/waf | awk 'NR==1{print $2}') WAF protection \033[1;32m";

else 
    echo "waf results exits: "
    echo -e "\033[0;32m \bThe web application is behinde\033[0;31m $(cat results/waf | awk 'NR==1{print $2}') WAF protection \033[1;32m"
fi

#finding subdomains 
echo -e "Gathering subdomains from crt.sh, markleap.com, assetfinder, subfinder and dnsmap with built-in wordlist\n"
if [[ ! -f ./results/subs ]]; then

    echo -e "gathering subdomains from crt.sh"
    curl -s https://crt.sh/\?q\=%\.$domain\&output=json | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u -V > results/crt_domains.txt

    echo -e "gathering subdomains from markleap.com"
    curl -s https://api.merklemap.com/search\?query=\*.$domain\&page=0\&output=json -X GET | \
        jq  -s '.[].results | .[].domain' | sed -e 's/[\*\"]//g'  | sed -e 's/^\.//g' | sort -u -V >> results/crt_domains.txt 

    echo -e "gathering subdomains using assetfinder (by Tom Hudson aka. tomnomnom)"
    # we are using set +m to maintain job control on a background job otherwise we had to source the script 
    set +m; { assetfinder --subs-only "$domain" > results/subs1 & } 2>/dev/null
    duration_counter "assetfinder"
    sed -i -e 's/^\*\.//g'  results/subs1 | sort -u -V > results/subs1

    echo -e "gathering subdomains using subfinder by projectdiscovery"
    set +m; { subfinder -all -d "$domain" -silent -o results/subs2  & } &>/dev/null 
    duration_counter "subfinder"

    echo -e "gathering subdomains using dnsmap with built-in wordlist"
    set +m; { dnsmap "$domain" -r results/dnsmap_results & } &>/dev/null;
    duration_counter "dnsmap"


    #cleaning the subdomains 
    cat results/dnsmap_results | sed -e 's/^IP .*$//g' | grep -Eo "([a-zA-Z]*\..*){1,}$" > results/dnsmap
    cat results/crt_domains.txt results/subs1 results/subs2 results/dnsmap | sort -u -V > results/subs && 
        rm results/subs2 results/subs1 results/crt_domains.txt results/dnsmap;

else
    echo -e "\nsubdomains file already exist"
fi 

# deep subdomain bruteforce if asked for  
if [[ "$3" == "--deep" ]]; then
    if [[ ! -f ./results/csv_ffuf_result ]]; then  

        echo "ffuf subdomains brt is running approximelty 6-7 minute duration"

        set +m; { ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u https://FUZZ.booking.ir -o results/subs.json -of json -noninteractive & } &>/dev/null 
        duration_counter "ffuf"

        cat results/subs.json| jq -s '.[].results'| jq -r '.[].host'| sort -u -V > results/ffuf_subs_result
        cat results/subs.json| jq -s '.[].results'| jq -r '.[] | [.host, .url, .redirectlocation, .status ] | @csv'| \
            sed -e '1s/^/subdomain,url,redirect_location,status\n/g' > results/csv_ffuf_result;

        cat results/subs results/ffuf_subs_result | sort -u -V > results/subs && 
            rm results/ffuf_subs_result results/subs.json 

    else 
        echo "result for deep subdomain gathering already exist" 
    fi 

else
    echo "not running deep subdomain gathering"
fi 

cat results/subs | inscope | sort -u -V > results/inscope_subs 

#cheking subdomains are up or extracting the body and headers 
if [[ ! -f results/alive_subs ]]; then 
    echo "cheking for alive subdomains using httprobe (a tool also by tomnomnom)"
    cat results/inscope_subs | httprobe -prefer-https > results/alive_subs
else 
    echo "alive sub domains already gathered"
fi
if [[ ! -d results/fff_res ]]; then
    echo "gathering response headers and body with fff (a tool also by tomnomnom)"
    cat results/alive_subs | fff -d 80 -H -b -S -o results/fff_res &> /dev/null  
else 
    echo "fff already have results stored!"
fi 

# using waybackpy and urlfinder for gathering urls from archive.org  
sleep 1

if [[ ! -f ./results/wayback_urls ]]; then
    echo "gathering urls from archive in background using waybackpy and urlfinder"
    set +m; { waybackpy -u $domain -ku -sub -h >> results/urls2 & } &>/dev/null 
    duration_counter "waybackpy"

    set +m; { urlfinder -list results/subs -silent -o results/urls1 & } &>/dev/null
    duration_counter "urlfinder"

    echo "sorting the urls for you"
    cat results/urls1 results/urls2 | sort -u -V > results/wayback_urls;
    rm -v results/urls1 results/urls2 

else 
    echo "archive urls already exists in results directory!"
fi

#using katana for crawling 
sleep 1
mkdir -p results/katana_results 
if [[ ! -f results/katana_results/crawl_result && ! -d results/katana_results/respones ]]; then
    echo "lets crawl in background using katana (a tool by discoveryproject)"
    set +m; { katana -silent -d 10 -list results/subs -o results/katana_results/crawl_result -srd results/katana_results/respones -ob -or & } &>/dev/null
else
    echo "katana results exists!"
fi

# using amass in background for enumeration! 
sleep 1 
if [[ ! -f results/amass_enum ]]; then
    echo "Runing amass for a for enum"   
    set +m; { amass enum -silent -passive -d $domain -o results/amass_enum & } &>/dev/null 
else 
    echo "amass enumeration results exist"
fi

# gathering ips for hosting and cleaning them for nmap usgae also saving the dns file 
sleep 1 
echo "cheking the $domain for host ips and dns levels"
if [[ ! -f results/dig_results ]]; then 
    dig $domain > results/dig_results 
    dig @8.8.8.8 +short NS booking.ir > results/ns_dns && sed -i -e 's/.$//g' results/ns_dns
else 
    echo "dig results already exists"
fi
if [[ ! -f  results/ns_lookup_res ]]; then 
    nslookup $domain > results/ns_lookup_res
else 
    echo "nslookup results already exist"
fi
if [[ ! -f hosted_on || ! -f results/ips.txt ]]; then 
    host "$domain" > hosted_on
    grep -oP '(\d{1,3}\.){3}\d{1,3}' hosted_on > results/ips.txt && rm hosted_on 
else 
    echo "ips alredy generated"
fi 

# running nmap with slow speed (-T2) so that the host won't reject us 
sleep 1 
echo "ips are generated\nStarting Namp scan in background by default for 1000 ports"
if [[ ! -f results/nmap_results ]]; then
    set +m;{ nmap -A -T2 -sC -iL results/ips.txt -oN results/nmap_results & } &>/dev/null 
else 
    echo "nmap results exist"
fi 

# gathering compelte whois information 
sleep 1 
echo "gathering whois information"  
mkdir -p results/whois 
if [[ ! -d ./results/whois/domain_based  &&  ! -d ./results/whois/ip_based ]]; then
    mkdir -p results/whois/ip_based results/whois/domain_based
    echo "gathering whois information on ip addresses"
    while read ip; do
        whois $ip > results/whois/ip_based/$ip 
    done < results/ips.txt

    echo "gathering whois information on domains" 
    while read domain_name; do
        whois -I $domain_name  > results/whois/domain_based/$domain_name
    done < results/subs
else
    echo "whois information already exist"
fi

# running gobuster on a small list for bruteforecing possilble direcotories 
sleep 1 
echo "running gobuseter in background both for lower case and upper case directory enum"
if [[ ! -f ./results/dirs_small ]]; then
    set +m; { 
    gobuster dir -u https://booking.ir \
        -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt \
        --timeout 5s  -t 50 -r -o results/dirs_small & 
    } &>/dev/null        

else  
    echo "gobuster results on small directory list results exits"
fi 
sleep 2 
if [[ ! -f ./results/dirs_lower_small ]]; then
    set +m; { 
    gobuster dir -u https://booking.ir\
        -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt\
        --timeout 5s  -t 50 -r -o results/dirs_lower_small &
    } &>/dev/null 

else 
    echo "gobuster results on lower case small directory list results exits"
fi 

# cheking for subdomain take over possibility with subzy cleaning the output json if and vulnerabiliy exist
sleep 1 
if [[ ! -f results/subzy_out ]]; then
    echo "cheking for subdomain takeover possible vulnerabilities using subzy tool"   
    set +m; { subzy run  --targets results/alive_subs --hide_fails --verify_ssl --vuln --https --timeout 5 --output results/subzy_out & } &>/dev/null 
    duration_counter "subzy"
    echo "cheking if there is any results for subdomain takeover if not deleting the files!"
    sleep 1 
    if [[ $(jq -e '. == null' results/subzy_out) = true || $(jq -e '. == []' results/subzy_out) = true ]]; then 
        echo "no possible subdomain takeover found by subzy!"
    else
        cat results/subzy_out | jq -r '.[].subdomain' | sort -u > results/possible_sub_takeover && rm results/subzy_out
        echo "Possible subdomain take over urls are stored in results"
    fi
else
    echo "subzy results exist"
    fi

    end_of_script
    secs=$SECONDS
    echo $(printf '\nthe whole script took %dh:%dm:%ds to finish\n' $((secs/3600)) $((secs%3600/60)) $((secs%60)))
