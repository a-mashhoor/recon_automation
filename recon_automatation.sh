#!/usr/bin/env zsh

#
#
# Author Arshia Mashhoor (l0uiew)
# github https://github.com/a-mashhoor/recon_automation.git

# Comments? one or two not in the mood for them for my freaking personal automation script
# use it as it is or leave not, not my problem I'm not your god damn babysiter ! by the way
# don't be an ahole use this shit responsivly on the freaking scope where the hell you are allowed
# to do enum or fuzzing  etcetra etcetra
#
#
#

emulate -LR zsh
setopt extendedglob
unsetopt CASE_MATCH
set +x
unsetopt xtrace

source ./funcs.sh


SUBS_TEMP=$(mktemp -p /tmp )
WAYBACK_TEMP=$(mktemp -p /tmp )
IPs_TEMP=$(mktemp -p /tmp )
DMAP_TEMP=$(mktemp -p /tmp )

declare -g SUBS_COUNT=0
declare -g L_SUBS_COUNT=0

function main(){
  _init_terminal
  parse_args "$@"
  print_header
  echo "${COLORS[BLUE]}Target domain: $domain${COLORS[RESET]}"
  _online
  echo -e "${COLORS[GREEN]}Starting the Recon...${COLORS[RESET]}"
  mkdir -p results
  if ! check_ssl "$domain"; then
    exit 0
  fi

  waf_det
  sub_g
  #sub_take subzy problem (i'll replace it with my own tool soon enough)
  headers
  wayback
  crawling
  enum
  dns_e
  basic_nmap
  who_is
  dir_brut
  rm -rf SUBS_TEMP WAYBACK_TEMP IPs_TEMP DMAP_TEMP
  end_of_script
  echo -e "${COLORS[GREEN]}The whole script took $(_format_time "$SECONDS") to finish${COLORS[RESET]}"
}


function parse_args(){
  zmodload zsh/zutil

  local -A opts
  typeset -g domain scope_file deep_scan=0

  zparseopts -D -F -A opts -- \
    d:=domain -domain:=domain \
    c:=scope -scope:=scope \
    h=help -help=help \
    -deep=deep || { usage; exit 1 }

  if (( ${+opts[-h]} )) || (( ${+opts[--help]} )); then
    usage
    exit 0
  fi

  domain="${opts[-d]:-${opts[--domain]}}"
  if [[ -z "$domain" ]]; then
    print -P "${COLORS[RED]}err: Domain argument is required${COLORS[RESET]}" >&2
    usage
    exit 1
  fi

  if ! validate_domain "$domain"; then
    exit 1
  fi

  typeset -g use_scope=0
  if (( ${+opts[-scope]} )) || (( ${+opts[--scope]} )); then
    scope_file=${opts[--scope]:-${opts[-scope]}}
    if ! validate_scope_file "$scope_file"; then
      exit 1
    fi
    use_scope=1
  else
    print -P "${COLORS[RED]}war: Not using scope${COLORS[RESET]}" >&2
  fi


  if (( ${+opts[--deep]} )); then
    deep_scan=1
  fi

}


function _online(){
  # am I online?
  if ! check_internet; then
    echo "${COLORS[RED]}err: Internet connection failed${COLORS[RESET]}" >&2
    echo "Network diagnostics:" >&2
    echo "  - Active interface: ${active_interface:-None}" >&2
    echo "  - Local IP: ${local_ip:-Not assigned}" >&2
    echo "  - Gateway: ${gateway_ip:-Not found}" >&2
    echo "Possible solutions:" >&2
    [[ -n "$gateway_ip" ]] && echo "  - Verify gateway is reachable (try ping $gateway_ip)" >&2
    echo "  - Check DNS settings (try ping 1.1.1.1) or your Physcial connection WIFI/Eth" >&2
    [[ -n "$active_interface" ]] && echo "  - Verify interface $active_interface has valid IP" >&2
    exit 1
  fi

  echo "${COLORS[GREEN]}Internet connection verified via $active_interface${COLORS[RESET]}"
  echo "  - Local IP: $local_ip"
  echo "  - Gateway: $gateway_ip"

  # is it online?
  st_code=$(curl -s -o /dev/null -w "%{http_code}" $domain 2>/dev/null)
  if [[ -n "$st_code" && "$st_code" -eq 000 ]]; then
    echo -e "${COLORS[RED]}Connection problem check you connection${COLORS[RESET]}"
    exit 1
  fi
  if [[ "$st_code" -lt 500 ]]; then
    echo -e "${COLORS[GREEN]}Website is up (HTTP $st_code) - proceeding...${COLORS[RESET]}"
  else
    echo -e "${COLORS[RED]}Website is down or unreachable (HTTP ${st_code:-"No response"}) - exiting${COLORS[RESET]}" >&2
    exit 1
  fi
}


function waf_det(){
  echo -e "${COLORS[BLUE]}Checking for WAF...${COLORS[RESET]}\n"
  if [[ ! -f results/waf ]]; then
    wafw00f "$domain" -a  --format=json -o results/waf &>/dev/null &&
      echo -e "${COLORS[GREEN]}The web application is behind ${COLORS[RED]}$(cat results/waf | jq -r '.[] | select(.detected == true) | .firewall' | paste -sd "," -) WAF protection ${COLORS[RESET]}"

  else
    echo "${COLORS[BLUE]}WAF results exist: ${COLORS[RESET]}"
    echo -e "${COLORS[GREEN]}The web application is behind ${COLORS[RED]}$(cat results/waf |  jq -r '.[] | select(.detected == true) | .firewall' | paste -sd "," -) WAF protection ${COLORS[RESET]}"
  fi
}

function sub_g(){

  echo -e "${COLORS[BLUE]}Gathering subdomains from crt.sh, merklemap.com, assetfinder, subfinder and dnsmap with built-in wordlist${COLORS[RESET]}\n"
  if [[ ! -f ./results/subs ]]; then
    echo -e "${COLORS[CYAN]}Gathering subdomains using subfinder${COLORS[RESET]}"
    set +m; { subfinder -all -d "$domain" -silent -o SUBS_TEMP & } &>/dev/null
    duration_counter "subfinder"

    echo -e "${COLORS[CYAN]}Gathering subdomains using assetfinder${COLORS[RESET]}"
    set +m; { assetfinder --subs-only "$domain" | sed -e 's/^\*\.//g' >> SUBS_TEMP & } 2>/dev/null
    duration_counter assetfinder

    echo -e "${COLORS[CYAN]}Gathering subdomains using dnsmap with built-in wordlist${COLORS[RESET]}"
    set +m; { dnsmap "$domain" -d 5 > DMAP_TEMP & } &>/dev/null
    duration_counter "dnsmap"
    grep -oP '(\d{1,3}\.){3}\d{1,3}' DMAP_TEMP >> IPs_TEMP
    grep -vP '(\d{1,3}\.){3}\d{1,3}' DMAP_TEMP | grep -v "+" | grep -ve "^dnsmap" >> SUBS_TEMP


    echo -e "${COLORS[CYAN]}Gathering subdomains from crt.sh${COLORS[RESET]}"
    curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' | sed -e 's/\*\.//g' >> SUBS_TEMP

    echo -e "${COLORS[CYAN]}Gathering subdomains from merklemap.com${COLORS[RESET]}"
    curl -s "https://api.merklemap.com/search?query=*.$domain&page=0&output=json" -X GET |
      jq -s '.[].results | .[].domain' | sed -e 's/[\*\"]//g' | sed -e 's/^\.//g' >> SUBS_TEMP

    sort -u -V SUBS_TEMP > results/subs
  else
    echo -e "${COLORS[YELLOW]}Subdomains file already exists${COLORS[RESET]}"
  fi

  if (( deep_scan )); then
    echo "${COLORS[BLUE]}Performing deep scan (subdomain brute force)${COLORS[RESET]}"

    if [[ ! -f ./results/csv_ffuf_result ]]; then
      echo "${COLORS[CYAN]}ffuf subdomains brute force is running (approximately 6-7 minutes duration)${COLORS[RESET]}"

      set +m; { ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u "https://FUZZ.$domain" -o results/subs.json -of json -noninteractive & } &>/dev/null
      duration_counter "ffuf"

      jq -r '.results[].host' results/subs.json | sort -u -V >> SUBS_TEMP
      jq -r '.results[] | [.host, .url, .redirectlocation, .status] | @csv' results/subs.json |
        sed -e '1s/^/subdomain,url,redirect_location,status\n/' > results/csv_ffuf_result

      SUBS_TEMP >> results/subs
      rm -f results/subs.json

    else
      echo "${COLORS[YELLOW]}Result for deep subdomain gathering already exists${COLORS[RESET]}"
    fi
  else
    echo "${COLORS[BLUE]}Not running deep subdomain gathering${COLORS[RESET]}"
  fi

  (( use_scope )) && $(sort -u -V results/subs | inscope > results/inscope_subs) || $(sort -u -V results/subs > results/inscope_subs)

  if [[ ! -f results/alive_subs ]]; then
    echo "${COLORS[CYAN]}Checking for alive subdomains using httprobe${COLORS[RESET]}";
    cat results/inscope_subs | httprobe -prefer-https > results/alive_subs
  else
    echo "${COLORS[YELLOW]}Alive subdomains already gathered${COLORS[RESET]}"
  fi
  L_SUBS_COUNT=$(l_counter results/alive_subs)
  SUBS_COUNT=$(l_counter results/inscope_subs)
  echo "${COLORS[GREEN]}FOUND total ${SUBS_COUNT} subdomains which ${L_SUBS_COUNT} are alive${COLORS[RESET]}"

}

# i need to edit subZy source code it hase a problem but fuck it not in the mood for it later
function sub_take(){
  if [[ ! -f results/subzy_out ]]; then
    echo "${COLORS[CYAN]}Checking for subdomain takeover vulnerabilities using subzy${COLORS[RESET]}"
    set +m; { subzy run --targets results/alive_subs --hide_fails --verify_ssl --vuln --https --timeout 5 --output results/subzy_out & } &>/dev/null
    duration_counter "subzy"
    if [[ -f results/subzy_out ]]; then
      if [[ $(jq -e '. == null' results/subzy_out) = true || $(jq -e '. == []' results/subzy_out) = true ]]; then
        echo "${COLORS[YELLOW]}No possible subdomain takeover found by subzy${COLORS[RESET]}"
        rm -f results/subzy_out
      else
        jq -r '.[].subdomain' results/subzy_out | sort -u -V > results/possible_sub_takeover
        echo "${COLORS[RED]}Possible subdomain takeover URLs found and stored in results${COLORS[RESET]}"
      fi
    fi
  else
    echo "${COLORS[YELLOW]}Subzy results exist${COLORS[RESET]}"
  fi
}

function headers(){
  if [[ ! -d results/fff_res ]]; then
    echo "${COLORS[CYAN]}Gathering response headers and body with fff${COLORS[RESET]}"
    cat results/alive_subs | fff -d 80 -H -b -S -o results/fff_res &>/dev/null
  else
    echo "${COLORS[YELLOW]}fff already has results stored${COLORS[RESET]}"
  fi
}


function wayback(){
  if [[ ! -f ./results/wayback_urls ]]; then
    echo "${COLORS[CYAN]}Gathering URLs from archive in background using waybackpy and urlfinder${COLORS[RESET]}"

    set +m; { urlfinder -list results/subs -silent -o WAYBACK_TEMP & } &>/dev/null
    duration_counter "urlfinder"

    set +m; { waybackpy -u "$domain" -ku -sub -h >> WAYBACK_TEMP & } &>/dev/null
    duration_counter "waybackpy"

    echo "${COLORS[BLUE]}Sorting the URLs${COLORS[RESET]}"

    sort -u -V WAYBACK_TEMP > results/wayback_urls

  else
    echo "${COLORS[YELLOW]}Archive URLs already exist in results directory${COLORS[RESET]}"
  fi
}

function crawling(){
  mkdir -p results/katana_results
  if [[ ! -f results/katana_results/crawl_result && ! -d results/katana_results/respones ]]; then
    echo "${COLORS[CYAN]}Crawling in background using katana${COLORS[RESET]}"
    set +m; { katana -silent -d 10 -list results/subs -o results/katana_results/crawl_result -srd results/katana_results/respones -ob -or & } &>/dev/null
  else
    echo "${COLORS[YELLOW]}Katana results exist${COLORS[RESET]}"
  fi
}

function enum(){
  if [[ ! -f results/amass_enum ]]; then
    echo "${COLORS[CYAN]}Running amass for enumeration${COLORS[RESET]}"
    set +m; { amass enum -silent -passive -d "$domain" -o results/amass_enum & } &>/dev/null

  else
    echo "${COLORS[YELLOW]}Amass enumeration results exist${COLORS[RESET]}"
  fi
}


function dns_e(){
  local dir=results/dns_results
  echo "${COLORS[CYAN]}Checking the $domain for DNS records and gathering IPs${COLORS[RESET]}"
  if [[ ! -d "$dir" ]]; then
    mkdir -p "$dir"
  else
    echo "${COLORS[YELLOW]}dns results dir already exist: $dir ${COLORS[RESET]}"
  fi
  if [[ -n $(ls -A "$dir") ]]; then
    setopt dotglob
    files=("$dir"/*(.))
    unsetopt dotglob
    file_count=${#files}
  fi

  if [[ ! -n $(ls -A "$dir") ]] || [[ file_count -ne $(( L_SUBS_COUNT + 1 )) ]];then
    cat results/alive_subs |  xargs -I {} zsh -c 'u="$1";d="$2"; dnsr -d "$u" -j -o "$d/""${u#*://}"' _ {} "$dir" &>/dev/null
    dig @8.8.8.8 +short NS "$domain" > results/dns_results/ns_record && sed -i -e 's/.$//g' results/dns_results/ns_record
    duration_counter "dig"
  else
    echo "${COLORS[YELLOW]}dns results already exist${COLORS[RESET]}"
  fi

  if [[ ! -f results/hosted_on || ! -f results/ips ]]; then
    cat results/alive_subs | xargs -I {} host "{}" > results/hosted_on
    grep -oP '(\d{1,3}\.){3}\d{1,3}' results/hosted_on >> IPs_TEMP
    sort -u -V IPs_TEMP > results/ips
  else
    echo "${COLORS[YELLOW]}IPs already generated${COLORS[RESET]}"
  fi
}

function basic_nmap(){
  echo "${COLORS[CYAN]}Starting Nmap scan in background (1000 ports)${COLORS[RESET]}"
  if [[ ! -f results/nmap_results ]]; then
    set +m; { nmap -A -T2 -sC -iL results/ips -oN results/nmap_results & } &>/dev/null
  else
    echo "${COLORS[YELLOW]}Nmap results exist${COLORS[RESET]}"
  fi
}


function who_is(){
  echo "${COLORS[CYAN]}Gathering whois information${COLORS[RESET]}"
  mkdir -p results/whois
  if [[ ! -d ./results/whois/domain_based && ! -d ./results/whois/ip_based ]]; then
    mkdir -p results/whois/ip_based results/whois/domain_based
    echo "${COLORS[BLUE]}Gathering whois information on IP addresses${COLORS[RESET]}"
    while read -r ip; do
      set +m; {timeout 10 whois -Ia -H "$ip" > results/whois/ip_based/"$ip"} 2>/dev/null
    done < results/ips

    echo "${COLORS[BLUE]}Gathering whois information on domains${COLORS[RESET]}"
    while read -r domain_name; do
      set +m;{timeout 10 whois -Ia "$domain_name" > results/whois/domain_based/"$domain_name"} 2>/dev/null
    done < results/subs
  else
    echo "${COLORS[YELLOW]}Whois information already exists${COLORS[RESET]}"
  fi
}


function dir_brut(){
  # in not deep already implemented bitches
  echo "${COLORS[CYAN]}Running gobuster for directory enumeration${COLORS[RESET]}"
  if [[ ! -f ./results/dirs_small ]]; then
    set +m;{ gobuster dir -u "https://$domain" \
      -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt \
      --timeout 5s -t 50 -r -o results/dirs_small &
    } &>/dev/null
  else
    echo "${COLORS[YELLOW]}Gobuster results (small directory list) exist${COLORS[RESET]}"
  fi

  if [[ ! -f ./results/dirs_lower_small ]]; then
    set +m;{ gobuster dir -u "https://$domain" \
      -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt \
      --timeout 5s -t 50 -r -o results/dirs_lower_small &
    } &>/dev/null
  else
    echo "${COLORS[YELLOW]}Gobuster results (lowercase small directory list) exist${COLORS[RESET]}"
  fi
  # if deep use big dict not feeling to added now maybe later
}

main "${@}"
