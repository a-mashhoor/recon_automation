#!/usr/bin/env zsh

typeset -gA COLORS=(
[RED]="\033[1;31m"
[GREEN]="\033[1;32m"
[YELLOW]="\033[1;33m"
[BLUE]="\033[1;34m"
[MAGENTA]="\033[1;35m"
[CYAN]="\033[1;36m"
[RESET]="\033[0m"
)

typeset -ga SPINNER=('⣾' '⣽' '⣻' '⢿' '⡿' '⣟' '⣯' '⣷')

_get_child_procs() {
  local -a procs
  local p cmd
  for p in $(ps -o pid= --ppid $$); do
    cmd=$(ps -o comm= -p $p)
    case $cmd in
      (zsh|sh|bash|dash|ps|grep|pgrep|awk|sed|cut|tr|*[[:space:]]*)
        continue ;;
      (*)
        procs+=($p) ;;
    esac
  done
  echo ${procs[@]}
}

_format_time() {
  local elapsed=$1
  printf "%02d:%02d:%02d" $((elapsed/3600)) $((elapsed%3600/60)) $((elapsed%60))
}

# hiding ctrl-c
stty -echoctl

# trapping ctrl c
trap ctrl_c INT
ctrl_c() {
  echo -e "\n${COLORS[YELLOW]}Exiting the program based on Ctrl + C by user execution!${COLORS[RESET]}"

  local child_pids=($(_get_child_procs))
  if [[ ${#child_pids[@]} -eq 0 ]]; then
    echo "No background processes to kill"
  else
    for p in ${child_pids[@]}; do
      proc_name=$(ps -o comm= -p $p)
      echo "Killing process $p ($proc_name)"
      kill $p 2>/dev/null
    done
  fi
  echo -e "${COLORS[GREEN]}Closing the script${COLORS[RESET]}"
  exit 130
}

user_agr() {
  local yn=$1
  if [ -z "$yn" ]; then
    echo -e "\nNo response detected exiting the script"
    return 1
  fi
  case $yn in
    [yY])
      echo -e "\nUser agreed proceeding"
      sleep 1
      return 0 ;;
    [nN])
      echo -e "\nExiting the script..."
      sleep 1
      return 1 ;;
    *)
      echo -e "\nInvalid response!"
      return 1 ;;
  esac
}

_monitor_processes() {
  local name=$1
  local multi_mode=$2
  local start=$SECONDS
  local spin_idx=0
  local -a pids

  while true; do
    if [[ -n "$name" ]]; then
      pids=($(pgrep -u "$USER" -f "$name"))
    else
      pids=($(_get_child_procs))
    fi

    [[ ${#pids[@]} -eq 0 ]] && break;

    local status_msg
    if [[ -n "$name" ]]; then
      local etime=$(ps -o etime= -p ${pids[1]} 2>/dev/null | tr -d ' ')
      status_msg="${COLORS[CYAN]}${name} ${COLORS[MAGENTA]}is running ${COLORS[YELLOW]}▶ ${COLORS[BLUE]}PS: ${#pids[@]} ${COLORS[YELLOW]}▶ ${COLORS[GREEN]}TIME: $(_format_time $((SECONDS - start))) (${etime})"
    else
      status_msg="${COLORS[RED]}${SPINNER[$spin_idx]} ${COLORS[BLUE]}Running ${COLORS[GREEN]}$(_format_time $((SECONDS - start))) ${COLORS[YELLOW]}▶ ${COLORS[CYAN]}Waiting for completion..."
    fi

    echo -ne "\r${status_msg}${COLORS[RESET]} "
    spin_idx=$(((spin_idx + 1) % ${#SPINNER[@]}))

    for i in {1..5}; do
      sleep 0.2
      [[ -n "$name" ]] && pids=($(pgrep -u "$USER" -f "$name")) || pids=($(_get_child_procs))
      [[ ${#pids[@]} -eq 0 ]] && break 2
    done
  done

  local elapsed=$((SECONDS - start))
  if [[ -n "$name" ]]; then
    echo -e "\r${COLORS[GREEN]}✓ ${COLORS[CYAN]}${name} ${COLORS[YELLOW]}completed in ${COLORS[GREEN]}$(_format_time $elapsed)${COLORS[RESET]}"
  else
    echo -e "\r${COLORS[GREEN]}✓ All processes completed in $(_format_time $elapsed)${COLORS[RESET]}\n"
  fi
}

duration_counter() {
  local name=$1
  if [[ -z "$name" ]]; then
    echo "${COLORS[YELLOW]}No process name specified${COLORS[RESET]}"
    return 1
  fi

  pids=($(pgrep -u "$USER" -f "$name"))
  if [[ ${#pids[@]} -eq 0 ]]; then
    echo "${COLORS[YELLOW]}No processes found matching '$name'${COLORS[RESET]}"
    return 1
  fi

  _monitor_processes "$name"
}

end_of_script() {
  local child_pids=($(_get_child_procs))
  local -a background_procs

  for p in ${child_pids[@]}; do
    background_procs+=($(ps -o comm= -p $p))
  done

  if [[ ${#background_procs[@]} -gt 0 ]]; then
    echo "${COLORS[YELLOW]}The following processes are running in background:${COLORS[RESET]}"
    echo "${COLORS[CYAN]}${(u)background_procs}${COLORS[RESET]}"
    echo "${COLORS[MAGENTA]}This could take a long time (some tools may take hours)${COLORS[RESET]}"
    echo "${COLORS[RED]}You can exit early with Ctrl+C but results may be incomplete${COLORS[RESET]}"

    _monitor_processes ""
  else
    echo -e "${COLORS[GREEN]}✓ All processes have completed successfully${COLORS[RESET]}"
  fi
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

  # Check length
  if [[ ${#domain} -gt $max_length ]]; then
    echo "${COLORS[RED]}Error: Domain exceeds maximum length of $max_length characters${COLORS[RESET]}" >&2
    return 1
  fi

  # Basic regex check
  if ! [[ "$domain" =~ '^([a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,}$' ]]; then
    echo "${COLORS[RED]}Error: '$domain' doesn't appear to be a valid domain${COLORS[RESET]}" >&2
    return 1
  fi

  # Check each label (part between dots)
  local IFS="."
  local labels=(${=domain})
  for label in "${labels[@]}"; do
    # Check label length (1-63 chars)
    if [[ ${#label} -lt 1 || ${#label} -gt 63 ]]; then
      echo "${COLORS[RED]}Error: Domain part '$label' has invalid length (must be 1-63 characters)${COLORS[RESET]}" >&2
      return 1
    fi

    # Check label starts and ends with alphanumeric
    if ! [[ "$label" =~ '^[a-zA-Z0-9]' ]] || ! [[ "$label" =~ '[a-zA-Z0-9]$' ]]; then
      echo "${COLORS[RED]}Error: Domain part '$label' must start and end with a letter or digit${COLORS[RESET]}" >&2
      return 1
    fi

    # Check label contains only allowed chars
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



