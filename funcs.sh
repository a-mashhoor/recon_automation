#!/usr/bin/env zsh

_init_terminal() {
  stty sane
  stty -echoctl
  stty intr '^C'
  [[ -t 1 ]] || { echo "Not running in a terminal" >&2; exit 1; };


  export IFS=$' \t\n'
  unsetopt SINGLE_LINE_ZLE
  setopt INTERACTIVE_COMMENTS
  setopt NO_PROMPT_SP
  setopt NO_PROMPT_CR
}

_cleanup_terminal() {
  emulate -L zsh
  setopt localoptions
  unsetopt xtrace
  set +x
  stty sane 2>/dev/null
  echo "" >&2
}

trap _cleanup_terminal EXIT INT TERM
_init_terminal

typeset -gA COLORS=(
[RED]=$'\033[1;31m'
[GREEN]=$'\033[1;32m'
[YELLOW]=$'\033[1;33m'
[BLUE]=$'\033[1;34m'
[MAGENTA]=$'\033[1;35m'
[CYAN]=$'\033[1;36m'
[RESET]=$'\033[0m')

typeset -ga SPINNER=('⣾' '⣽' '⣻' '⢿' '⡿' '⣟' '⣯' '⣷')



_print_status() {
  local msg="$1"
  # Use direct terminal control sequences
  printf "\r\033[2K%s${COLORS[RESET]}" "$msg" >&2
  # Immediately flush output
  zle && zle flush-input 2>/dev/null || true
}


_get_child_procs() {
  local -a procs=()
  local p cmd
  for p in ${(f)"$(ps -o pid= --ppid $$ 2>/dev/null)"}; do
    cmd=$(ps -o comm= -p $p 2>/dev/null) || continue
    case $cmd in
      (zsh|sh|bash|dash|ps|grep|pgrep|awk|sed|cut|tr|*[[:space:]]*) continue ;;
      (*) procs+=($p) ;;
    esac
  done
  print -l $procs
}

_format_time() {
  local elapsed=$1
  printf "%02d:%02d:%02d" $((elapsed/3600)) $((elapsed%3600/60)) $((elapsed%60))
}

duration_counter() {
  local name=$1
  local start_time=$SECONDS
  local -a pids
  local elapsed etime formatted_elapsed

  # Get all PIDs for the process name
  pids=($(pgrep -u "$USER" -f "$name"))

  if [[ ${#pids[@]} -eq 0 ]]; then
    _print_status "${COLORS[YELLOW]}No processes found matching '$name'"
    return 1
  fi

  # Animation characters
  local spin_idx=0

  while true; do
    # Check if any processes are still running
    pids=($(pgrep -u "$USER" -f "$name"))
    [[ ${#pids[@]} -eq 0 ]] && break

    # Get elapsed time for the first process
    etime=$(ps -o etime= -p ${pids[1]} 2>/dev/null | tr -d ' ')

    # Calculate total elapsed time
    elapsed=$((SECONDS - start_time))
    formatted_elapsed=$(_format_time $elapsed)

    # Build status message
    local msg="${COLORS[RED]}${SPINNER[$spin_idx]} ${COLORS[CYAN]}${name} ${COLORS[MAGENTA]}is running "
    msg+="${COLORS[YELLOW]}▶ ${COLORS[BLUE]}PS: ${#pids[@]} ${COLORS[YELLOW]}▶ "
    msg+="${COLORS[GREEN]}TIME: ${formatted_elapsed} (${etime})"

    _print_status "$msg"

    # Update spinner
    spin_idx=$(((spin_idx + 1) % ${#SPINNER[@]}))

    # Sleep but allow quick exit
    for i in {1..10}; do
      sleep 0.1
      # Check if processes ended during sleep
      pids=($(pgrep -u "$USER" -f "$name"))
      [[ ${#pids[@]} -eq 0 ]] && break
    done
  done

  # Final message
  elapsed=$((SECONDS - start_time))
  formatted_elapsed=$(_format_time $elapsed)
  _print_status "${COLORS[GREEN]}✓ ${COLORS[CYAN]}${name} ${COLORS[YELLOW]}completed in ${COLORS[GREEN]}${formatted_elapsed}"
  echo  # Add newline after completion
}

end_of_script() {
  # Get all child processes using helper
  local child_pids=($(_get_child_procs))
  local background_procs=()
  local p cmd

  # Get unique process names
  for p in ${child_pids[@]}; do
    cmd=$(ps -o comm= -p $p 2>/dev/null || continue)
    background_procs+=($cmd)
  done

  if [[ ${#background_procs[@]} -gt 0 ]]; then
    echo "${COLORS[YELLOW]}The following processes are running in background:${COLORS[RESET]}"
    echo "${COLORS[CYAN]}${(u)background_procs}${COLORS[RESET]}"
    echo "${COLORS[MAGENTA]}This could take a long time (some tools like katana may take hours)${COLORS[RESET]}"
    echo "${COLORS[RED]}You can exit early with Ctrl+C but results may be incomplete${COLORS[RESET]}"

    local spin_idx=0
    local start=$SECONDS
    local elapsed time_str

    while true; do
      # Check if any background processes remain
      child_pids=($(_get_child_procs))
      [[ ${#child_pids[@]} -eq 0 ]] && break

      # Calculate elapsed time
      elapsed=$((SECONDS - start))
      time_str=$(_format_time $elapsed)

      # Build status message
      local msg="${COLORS[RED]}${SPINNER[$spin_idx]} ${COLORS[BLUE]}Running "
      msg+="${COLORS[GREEN]}${time_str} ${COLORS[YELLOW]}▶ "
      msg+="${COLORS[CYAN]}Waiting for completion..."

      _print_status "$msg"

      # Update spinner
      spin_idx=$(((spin_idx + 1) % ${#spin[@]}))

      # Sleep but check frequently
      for i in {1..5}; do
        sleep 0.2
        child_pids=($(_get_child_procs))
        [[ ${#child_pids[@]} -eq 0 ]] && break
      done
    done

    # Final completion message
    elapsed=$((SECONDS - start))
    time_str=$(_format_time $elapsed)
    _print_status "${COLORS[GREEN]}✓ All processes completed in ${time_str}"
    echo "\n"
  else
    _print_status "${COLORS[GREEN]}✓ All processes have completed successfully"
    echo
  fi
}

# hiding ctrl-c
stty -echoctl

# trapping ctrl c
trap ctrl_c INT

ctrl_c() {
  print -P "\n%F{yellow}Exiting the program based on Ctrl + C by user execution!%f"

  local child_pids=($(_get_child_procs))
  if [[ ${#child_pids[@]} -eq 0 ]]; then
    print "No background processes to kill"
  else
    for p in ${child_pids[@]}; do
      proc_name=$(ps -o comm= -p $p)
      print -P "%F{red}Killing process $p ($proc_name)%f"
      kill $p 2>/dev/null
    done
  fi
  print -P "%F{green}Closing the script%f"
  exit 130
}

user_agr() {
  local yn=$1
  if [ -z "$yn" ]; then
    echo -e "\n${COLORS[RED]}No response - exiting${COLORS[RESET]}"
    return 1
  fi
  case $yn in
    [yY])
      echo -e "\n${COLORS[GREEN]}User Agreed!${COLORS[RESET]}"
      sleep 0.3
      return 0 ;;
    [nN])
      echo -e "\n${COLORS[RED]}Timeout reached - assuming no${COLORS[RESET]}"
      sleep 0.3
      return 1 ;;
    *)
      echo -e "\n${COLORS[RED]}Invalid Response${COLORS[RESET]}"
      return 1 ;;
  esac
}

print_header() {
  print -P "%F{cyan}%B${(r:78::═:)}"
  print -Pn "%F{cyan}%B"
  figlet -c -w 150 -t "Recon Automation" | while read -r line; do
  echo "${COLORS[CYAN]}$line";done
  print -P "%F{white}%B\ngithub -->> https://github.com/a-mashhoor/recon_automation.git%f%k"
  print -P "%F{cyan}%B${(r:78::═:)}%f%k\n"
}

function usage() {
  local script_name=${funcfiletrace[1]%:*}
  script_name=${${script_name:t}:r}

  >&2 cat <<EOF
  Usage: $script_name -d DOMAIN [-c SCOPE_FILE] [--deep]

  Options:
  -d, --domain DOMAIN    Target domain to scan (required)
  -c, --scope SCOPE_FILE Path to .scope file (must have .scope extension)
  --deep             Perform deep subdomain brute force using ffuf
  -h, --help             Show this help message

EOF
}


function validate_scope_file() {
  echo "Checking for ./.scope file"

  local file=$1

  if [[ "$file" != *.scope ]]; then
    echo "${COLORS[RED]}Error: Scope file must have .scope extension${COLORS[RESET]}" >&2
    return 1
  fi

  if [[ ! -f "$file" ]]; then
    echo "${COLORS[RED]}Error: Scope file '$file' does not exist${COLORS[RESET]}" >&2
    return 1
  fi

  if [[ ! -r "$file" ]]; then
    echo "${COLORS[RED]}Error: Scope file '$file' is not readable${COLORS[RESET]}" >&2
    return 1
  fi

  if ! grep -q '[^[:space:]]' "$file" || ! grep -q . "$file" ; then
    echo "${COLORS[RED]}Error: Scope file '$file' is empty${COLORS[RESET]}" >&2
    return 1
  fi

  if grep -q -Eo "^(https|http|\.|\*|\.|\^)[a-zA-Z0-9./*?=_%:-].*(.\$)" "$file" || grep -q -Eo "([a-zA-Z]*\..*){1,}$" "$file"; then
    echo -e "\n.scope file contains valid URL-like content proceeding...\nScope file contains:\n"
    echo -e "${COLORS[YELLOW]}$(cat "$file")${COLORS[GREEN]}\n"
  else
    echo -e "\n${COLORS[YELLOW]}.scope file does not contain valid URL-like content exiting${COLORS[RESET]}" >/dev/stderr
    return 1
  fi

  return 0
}

validate_domain() {
  local domain=$1
  local max_length=255

  if [[ ${#domain} -gt $max_length ]]; then
    echo "${COLORS[RED]}Error: Domain exceeds maximum length of $max_length characters${COLORS[RESET]}" >&2
    return 1
  fi

  if ! [[ "$domain" =~ '^([a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,}$' ]]; then
    echo "${COLORS[RED]}Error: '$domain' doesn't appear to be a valid domain${COLORS[RESET]}" >&2
    return 1
  fi

  local IFS="."
  local labels=(${=domain})
  for label in "${labels[@]}"; do

    if [[ ${#label} -lt 1 || ${#label} -gt 63 ]]; then
      echo "${COLORS[RED]}Error: Domain part '$label' has invalid length (must be 1-63 characters)${COLORS[RESET]}" >&2
      return 1
    fi

    if ! [[ "$label" =~ '^[a-zA-Z0-9]' ]] || ! [[ "$label" =~ '[a-zA-Z0-9]$' ]]; then
      echo "${COLORS[RED]}Error: Domain part '$label' must start and end with a letter or digit${COLORS[RESET]}" >&2
      return 1
    fi

    if ! [[ "$label" =~ '^[a-zA-Z0-9-]+$' ]]; then
      echo "${COLORS[RED]}Error: Domain part '$label' contains invalid characters${COLORS[RESET]}" >&2
      return 1
    fi
  done

  return 0
}

check_internet() {
  local test_services=("1.1.1.1" "8.8.8.8" "www.google.com")

  declare -g active_interface=""
  declare -g local_ip=""
  declare -g gateway_ip=""
  declare -g interface_up=0

  # Find the active network interface
  for interface in $(ls /sys/class/net/ | grep -v -e '^lo$' -e '^docker'); do
    if [[ -e /sys/class/net/$interface/carrier ]] && [[ $(cat /sys/class/net/$interface/carrier) == 1 ]]; then
      interface_up=1
      active_interface=$interface
      local_ip=$(ip -o -4 addr show $interface | awk '{print $4}' | cut -d'/' -f1)
      gateway_ip=$(ip route show default dev $interface | awk '{print $3}')
      break
    fi
  done
  [[ $interface_up -eq 0 ]] && return 1

  for target in "${test_services[@]}"; do
    if ping -c1 -W2 "$target" &>/dev/null; then
      return 0
    fi
  done

  return 1
}

check_ssl() {
  local domain=$1
  local cert_info

  if ! cert_info=$(timeout 5 openssl s_client -connect "$domain:443" -servername "$domain" -showcerts 2>/dev/null | openssl x509 -noout -text 2>/dev/null); then
    echo "${COLORS[RED]}ERROR: Failed to connect to $domain:443${COLORS[RESET]}" >&2
    return 1
  fi

  if ! openssl s_client -connect "$domain:443" -servername "$domain" -quiet -verify_quiet -brief -no_ign_eof </dev/null 2>/dev/null; then
    echo "${COLORS[YELLOW]}WARNING: SSL certificate for $domain may be invalid or self-signed${COLORS[RESET]}" >&2
    echo "Certificate details:"
    echo "$cert_info" | grep -E 'Issuer:|Subject:|Not Before:|Not After :|DNS:'

    read -t 10 -qs "yn?Proceed despite certificate issues? [y/N] "
    if ! user_agr "$yn"; then {rm -rf results; return 1}; fi
  fi
  echo "${COLORS[GREEN]}Valid SSL certificate found for $domain${COLORS[RESET]}"
  return 0
}
