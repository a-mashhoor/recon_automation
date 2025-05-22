# Recon Automation

### **Description:**

First and foremost, recon automation is not a standalone tool;
rather, it is a script designed to automate the use of commonly utilized tools
by bug bounty hunters or web application penetration testers during the initial phase of penetration testing,
specifically the reconnaissance stage.

This script organizes the results by extracting useful information from each tool's output individually
and linking that information to subsequent tools for further data gathering. For example, it follows a sequence like "hosts → IPs → Nmap."


The script is created and tested on a Kali Linux machine, where all dependencies are also tested and installed.
Notably, the init.sh script checks for a Kali machine before installing the necessary dependencies.

I originally wrote this script for my personal use, but I thought others might enjoy the benefits of automation as well, so I decided to publish it!

### **Installation:**

#### Note: This script will force zsh (changes your shell from anything to zsh)!

just run
```shell
curl -fsSL https://raw.githubusercontent.com/a-mashhoor/recon_automation/master/init.sh | sudo bash -s --
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
