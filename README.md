# Recon Automation 

### **Description:**

First and foremost, recon automation is not a standalone tool; 
rather, it is a script designed to automate the use of commonly utilized tools 
by bug bounty hunters or web application penetration testers during the initial phase of penetration testing, 
specifically the reconnaissance stage.

This script organizes the results by extracting useful information from each tool's output individually 
and linking that information to subsequent tools for further data gathering. For example, it follows a sequence like "hosts → IPs → Nmap."

`small part of script:`

``` shell 
if [[ ! -f hosted_on || ! -f results/ips.txt ]]; then
    host "$domain" > hosted_on
    grep -oP '(\d{1,3}\.){3}\d{1,3}' hosted_on > results/ips.txt && rm hosted_on
else
    echo "ips already generated"
fi

# running Nmap with slow speed (-T2) so that the host won't reject us
sleep 1
echo "ips are generated\nStarting Namp scan in the background by default for 1000 ports"
if [[ ! -f results/nmap_results ]]; then
    set +m;{ nmap -A -T2 -sC -iL results/ips.txt -oN results/nmap_results & } &>/dev/null
else
    echo "nmap results exist"
fi
```

The script is created and tested on a Kali Linux machine, where all dependencies are also tested and installed. 
Notably, the init.sh script checks for a Kali machine before installing the necessary dependencies.

I originally wrote this script for my personal use, but I thought others might enjoy the benefits of automation as well, so I decided to publish it!

### **Installation:**

Just clone the script.
```
git clone https://github.com/a-mashhoor/recon_automation.git 
```
go to the `recon_automation` directory and run `sudo chmod a+x ./init.sh ./recon_automation` for granting execution permission 

The script uses several tools you can install them yourself or you can use the init.sh script before using the script itself 

To install the tools just run ` sudo ./init.sh ` and that's it.

then you can use the script inside its working directory 
but this is not very useful 

So for ease of use, you can make a symbolic link of script to your ~/.local/bin or  /usr/bin or any PATH you want 
if you used init.sh you already have your local path on your .zshrc file 
    if you don't just run the following
```
echo "export PATH=$PATH:~/.local/bin" >> ~/.zshrc 
```
for making a symbolic link and for it to work because we used a so-called library for our
separate functions and we source it to the script itself `source ./funcs` we can not make a symbolic link that 
works correctly! 
to achieve this we have to modify the source address because it's a relative PATH and we must replace it 
with the absolute PATH of the directory of the source code 
So first save the source code if you want it to be permanently saved 
then we can change the relative PATH to the absolute one 

Because the `source ./funcs.sh ` code is placed on the 11th line we can run this command to fix the issue

``` shell 
cat recon_automatation.sh|sed '11d' | awk 'NR==11{system(" echo 'source" "$(pwd)/funcs.sh' ")} {print}' > recon_automatation.sh
```
after this, we can use a symbolic link 
```shell
ln -s path/to/recon_automation.sh  ~/.local/bin/recon_aut 
```


### **Usage:**

you must provide a .scope file because the script uses tomnomnom's inscope tool 
you can read about the tool in this link [inscope tool](https://github.com/tomnomnom/hacks/tree/master/inscope).

In the `recon_automation` Directory, run: 

```shell 
./recon_automation.sh -d example.com 
./recon_automation.sh -d example.com --deep
``` 

Or if you followed the instructions:
```shell
recon_aut -d example.com
recon_aut -d example.com --deep
```

You can also choose to perform a deep subdomain brute force using ffuf by `--deep` switch at the end of the command! 
When the script finishes scanning it will provide you a directory full of different results very thoughtfully named results :)

**Happy hunting :)**


### **Disclaimer:**
these ethical hacking tools are intended for educational purposes and awareness training sessions only.
Or on in-scope domains of bug bounty programs 
Performing hacking attempts on computers that you do not own (without permission) is illegal! 
Do not attempt to gain access to a device that you do not own.
