#!/usr/bin/env zsh 

# this hides the control c
stty -echoctl

# trapping ctrl c and in case of ctrl c killing the background processes 
trap ctrl_c INT
ctrl_c () {
    echo -e "\n\033[1;33mexitng the program based on Ctrl + C by user execution! "
    processes=()
    for proc in $(ps --no-headers |grep -v zsh  | grep -v ps | grep -v grep | grep -v awk | awk '{print $1}'); do
        processes+=$proc
    done
    if [[ -z "${processes[@]}" ]]; then echo "no process to kill"; fi
    for p in ${processes[@]}; do echo "kililing precess $(ps --no-headers |grep "$p" | awk '{print $4}')"; kill $p ; done
    echo "\033[0;32mcolsing the script" 
    exit 
}

# simple case for user to accept something or not! 
user_agr () {  
    yn=$1
    if [ -z $yn ]; then 
        echo -e "\nNo response detected exiting the script"
        return 1
    fi 
    case $yn in
        y) 
            echo -e "\nOpening vim to create the .scope file"
            sleep 2 
            vim .scope
            return 0;;
        n)
            echo -e "\nExiting the script..."
            sleep 1
            return 1;;
        *)
            echo "\nInvalid response! "
            return 1;;
    esac
}

# counting the time a background process is running 
duration_counter () {
    name=$1
    while pgrep -u "$USER" "$name" > /dev/null ; do
        echo -ne "\r\033[0k\033[1;31m"$name" is ruuning! --> $(ps -eo pid,etime | grep "$(pgrep "$name")" | awk '{print $2}') <-- Duration";
        usleep 1080000
    done
    echo -e "\n\033[1;32m"
}

end_of_script () {
    if ps --no-headers |grep -v zsh  | grep -v ps | grep -v grep &>/dev/null ; then 
        echo "the below process are runing in background please wait until they are done: "
        echo "This could take very long time depend on the website size katana crawling may take up to couple of hours"
        echo -e "\033[1;36m$(ps --no-headers |grep -v zsh  | grep -v ps | grep -v grep | grep -v awk | awk '{print $4}')\033[1;32m"
        echo -e "\n\033[1;31mYou can always exist ealry with ctrl+c but the results won't be reliable"
        s=0
        m=0
        h=0
        while ps --no-headers |grep -v zsh  | grep -v ps | grep -v grep &>/dev/null ; do 
            sleep 1
            ((s++))
            if [[ $s -eq 60 ]];then
                s=0
                ((m++))
            fi
            if [[ $m -eq 60 ]];then 
                s=0
                m=0
                ((h++))
            fi
            echo -ne "\r\033[0k\033[1;31mThe tools are ruuning duration --> $h:$m:$s  <-- Thank you for your patience"
        done
    else 
        echo -e "\033[1;35mThe script is completely finished\033[1;32m"
    fi    
}
