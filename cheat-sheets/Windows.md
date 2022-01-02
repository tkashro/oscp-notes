# Windows

Due to Windows irregular way of naming their operating systems it can be a bit hard to keep track on. So here is a list of the desktop OS, and then a list of Servers.

#### Windows Desktop OS'

```text
Operating System     Version Number

Windows 1.0                    1.04
Windows 2.0                    2.11
Windows 3.0                    3
Windows NT 3.1                 3.10.528
Windows for Workgroups 3.11    3.11
Windows NT Workstation 3.5     3.5.807
Windows NT Workstation 3.51    3.51.1057
Windows 95                     4.0.950
Windows NT Workstation 4.0     4.0.1381
Windows 98                     4.1.1998
Windows 98 Second Edition      4.1.2222
Windows Me                     4.90.3000
Windows 2000 Professional      5.0.2195
Windows XP                     5.1.2600
Windows Vista                  6.0.6000
Windows 7                      6.1.7600
Windows 8.1                    6.3.9600
Windows 10                     10.0.10240
```

#### Windows Server

```text
Windows NT 3.51                  NT 3.51
Windows NT 3.5                   NT 3.50
Windows NT 3.1                   NT 3.10
Windows 2000                     NT 5.0     

    Windows 2000 Server
    Windows 2000 Advanced Server
    Windows 2000 Datacenter Server

Windows NT 4.0                   NT 4.0     

    Windows NT 4.0 Server
    Windows NT 4.0 Server Enterprise
    Windows NT 4.0 Terminal Server Edition

Windows Server 2003              NT 5.2     

    Windows Small Business Server 2003
    Windows Server 2003 Web Edition
    Windows Server 2003 Standard Edition
    Windows Server 2003 Enterprise Edition
    Windows Server 2003 Datacenter Edition
    Windows Storage Server

Windows Server 2003 R2           NT 5.2     

    Windows Small Business Server 2003 R2
    Windows Server 2003 R2 Web Edition
    Windows Server 2003 R2 Standard Edition
    Windows Server 2003 R2 Enterprise Edition
    Windows Server 2003 R2 Datacenter Edition
    Windows Compute Cluster Server 2003 (CCS)
    Windows Storage Server
    Windows Home Server

Windows Server 2008               NT 6.0     

    Windows Server 2008 Standard
    Windows Server 2008 Enterprise
    Windows Server 2008 Datacenter
    Windows Server 2008 for Itanium-based Systems
    Windows Server Foundation 2008
    Windows Essential Business Server 2008
    Windows HPC Server 2008
    Windows Small Business Server 2008
    Windows Storage Server 2008
    Windows Web Server 2008

Windows Server 2008 R2            NT 6.1     

    Windows Server 2008 R2 Foundation
    Windows Server 2008 R2 Standard
    Windows Server 2008 R2 Enterprise
    Windows Server 2008 R2 Datacenter
    Windows Server 2008 R2 for Itanium-based Systems
    Windows Web Server 2008 R2
    Windows Storage Server 2008 R2
    Windows HPC Server 2008 R2
    Windows Small Business Server 2011
    Windows MultiPoint Server 2011
    Windows Home Server 2011
    Windows MultiPoint Server 2010

Windows Server 2012               NT 6.2     

    Windows Server 2012 Foundation
    Windows Server 2012 Essentials
    Windows Server 2012 Standard
    Windows Server 2012 Datacenter
    Windows MultiPoint Server 2012

Windows Server 2012 R2            NT 6.3     

    Windows Server 2012 R2 Foundation
    Windows Server 2012 R2 Essentials
    Windows Server 2012 R2 Standard
    Windows Server 2012 R2 Datacenter

Windows Server 2016     2016       NT 10.0
```

#### Active directory

From Windows 2000 and on the application Active directory has been program used for maintaining the central database of users and configurations.

#### Domain controller

Any windows computer can be configured to be a domain controller. The domain controller manages all the security aspects of the interaction between user and domain. There are usually a least two computers configured to be domain-controllers. In case one breaks down.

If you have compromised a machine that belong to a domain you can check if it has any users. DC:s don't have local users.

If you run enum4linux you can look out for this section

```text
Nbtstat Information
<1c> - <GROUP> B <ACTIVE>  Domain Controllers
```

#### SMB

On networks that are based on Linux and you need to integrate a windows machine you can use SMB to do that.

#### Kerberos

Kerberos is a network authentication protocol. The original protocol is used by many unix-systems. Windows have their own version of the Kerberos protocol, so that it works with their NT-kernel. It is used by windows Domains to authenticate users. But kerberos can also be found in several unix-operating systems. Kerberos was not built by windows, but long before.

I think a machine that has port 88 open (the default kerberos port) can be assumed to be a Domain Controller.

When a user logs in to the domain Active Directory uses Kerberos to authenticate the user. When the user insert her password it gets one-way encrypted and sent with Kerberos to the Active directory, which then compares it with its password database. The Key Distribution Center responds with a TGI ticket to the user machine.

#### Directory Structure

[https://en.wikipedia.org/wiki/Directory_structure](https://en.wikipedia.org/wiki/Directory_structure)

# Windows Commands

The equivalent to the Linux command `;` as in

`echo "command 1" ; echo "command 2"`

is

`dir & whoami`

#### Dealing with files

Delete file

`del` 

Create folder/directory

`md folderName`

Show hidden files

`dir /A`

Print out file content, like cat

`type file.txt`

grep files

`findstr file.txt`

Find command help

`help dir`

#### Network

Show network information

`netstat -an`

Show network adapter info

`ipconfig`

Ping another machine

`ping 192.168.1.101`

Traceroute

`tracert`

#### Processes

List processes

`tasklist`

Kill a process

`taskkill /PID 1532 /F`

#### Users

```text
net users

# Add user
net user hacker my_password /add
net localgroup Administrator hacker /add

# Check if you are part of a domain
net localgroup /domain

# List all users in a domain
net users /domain
```

#### Mounting - Mapping

In the windows world mounting is called mapping.

If you want to see which drives are mapped/mounted to your file-system you can use any of these commands:

```text
# This is the most thorough
wmic logicaldisk get deviceid, volumename, description

# But this works too
wmic logicaldisk get name
wmic logicaldisk get caption

# This can be slow. So don't kill your shell!
fsutil fsinfo drives

# With powershell
get-psdrive -psprovider filesystem

# This works too, but it is interacive. So it might be dangerous work hackers
diskpart
list volume

# Map only network drives
net use
```

The command to deal with mounting/mapping is `net use`

Using `net use` we can connect to other shared folder, on other systems. Many windows machines have a default-share called IPC (Interprocess communication share). It does not contain any files. But we can usually connect to it without authentication. This is called a **null-session**. Although the share does not contain any files it contains a lot of data that is useful for enumeration. The Linux-equivalent of `net use` is usually `smbclient`.

```text
net use \\IP address\IPC$ "" /u:""
net use \\192.168.1.101\IPC$ "" /u:""
```

If you want to map a drive from another network to your filesystem you can do that like this:

```text
# This will map it to drive z
net use z: \\192.168.1.101\SYSVOL

# This will map it to the first available drive-letter
net use * \\192.168.1.101\SYSVOL
```

Here you map the drive to the letter `z`. If the command is successful you should now be able to access those files by entering the `z` drive.

You enter the z-drive by doing this:

```text
C:\>z:
Z:\

# Now we switch back to c
Z:\>c:
C:\
```

#### Remove a network drive - umount it

First leave the drive if you are in it:

```text
c:
net use z: /del
```

