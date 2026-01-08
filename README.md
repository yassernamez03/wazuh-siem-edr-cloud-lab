# 🛡️ Wazuh SIEM/EDR Lab - Multi-OS Security Monitoring

[![AWS](https://img.shields.io/badge/AWS-Cloud-orange)](https://aws.amazon.com/)
[![Wazuh](https://img.shields.io/badge/Wazuh-4.7-blue)](https://wazuh.com/)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-22.04-E95420)](https://ubuntu.com/)
[![Windows](https://img.shields.io/badge/Windows-Server%202022-0078D6)](https://www.microsoft.com/)

## 📋 Description

Ce projet présente un **atelier pratique de sécurité des endpoints** combinant les approches **SIEM** (Security Information and Event Management) et **EDR** (Endpoint Detection and Response) avec **Wazuh**, déployé sur **AWS Learner Lab**.

L'atelier couvre la mise en place d'une plateforme complète de supervision de sécurité dans un environnement multi-OS (Linux et Windows), avec génération et analyse d'événements de sécurité réels.

## 🎯 Objectifs

- Déployer une architecture de sécurité complète sur AWS
- Configurer Wazuh (SIEM/EDR) pour la supervision multi-OS
- Générer et analyser des événements de sécurité
- Comprendre les différences entre SIEM et EDR
- Pratiquer le threat hunting et l'analyse de logs
- Implémenter les concepts IAM/PAM

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                    AWS VPC                          │
│  ┌──────────────────────────────────────────────┐   │
│  │             Subnet (Public)                  │   │
│  │                                              │   │
│  │  ┌─────────────────┐                         │   │
│  │  │ Wazuh-Server    │  Port 443 (Dashboard)   │   │
│  │  │ Ubuntu 22.04    │◄─────────────────────   │   │
│  │  │ t3.large        │                         │   │
│  │  │ 30GB Storage    │                         │   │
│  │  └────────┬────────┘                         │   │
│  │           │ Port 1514 (Agents)               │   │
│  │           │ Port 1515 (Enrollment)           │   │
│  │      ┌────┴─────┬──────────────┐             │   │
│  │      │          │              │             │   │
│  │  ┌───▼────┐  ┌──▼──────┐   ┌──▼──────┐       │   │
│  │  │ Linux  │  │Windows  │   │ Future  │       │   │
│  │  │ Client │  │ Client  │   │ Agents  │       │   │
│  │  │Ubuntu  │  │Server   │   │  ...    │       │   │
│  │  │t2.micro│  │t2.medium│   └─────────┘       │   │
│  │  └────────┘  └─────────┘                     │   │
│  └──────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

## 🚀 Infrastructure AWS

### Instances EC2

| Instance | OS | Type | Storage | Rôle |
|----------|-------|---------|---------|------|
| Wazuh-Server | Ubuntu 22.04 | t3.large | 30GB | Manager + Indexer + Dashboard |
| Linux-Client | Ubuntu 22.04 | t2.micro | 8GB | Agent Wazuh (Supervised) |
| Windows-Client | Windows Server 2022 | t2.medium | 30GB | Agent Wazuh + Sysmon |

### Security Groups

**Wazuh-Server-SG:**
- 22/TCP ← Admin IP (SSH)
- 443/TCP ← Admin IP (Dashboard)
- 1514/TCP ← Wazuh-Clients-SG (Agent communication)
- 1515/TCP ← Wazuh-Clients-SG (Agent enrollment)

**Wazuh-Clients-SG:**
- 22/TCP ← Admin IP (SSH - Linux)
- 3389/TCP ← Admin IP (RDP - Windows)

## 📦 Installation

### Prérequis

- Compte AWS Learner Lab actif
- Navigateur web moderne
- Client SSH (terminal Linux/Mac ou PuTTY pour Windows)
- Client RDP (Microsoft Remote Desktop)

### 1️⃣ Déploiement Infrastructure AWS

```bash
# Créer les Security Groups
aws ec2 create-security-group --group-name Wazuh-Server-SG --description "SG for Wazuh Server"
aws ec2 create-security-group --group-name Wazuh-Clients-SG --description "SG for Wazuh Clients"

# Configurer les règles (voir documentation détaillée)
# Lancer les 3 instances EC2 avec les configurations appropriées
```

### 2️⃣ Installation Wazuh Server

```bash
# Connexion au serveur
ssh -i wazuh-lab-key.pem ubuntu@<WAZUH-SERVER-IP>

# Mise à jour système
sudo apt update && sudo apt -y upgrade

# Téléchargement et installation Wazuh All-in-One
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash wazuh-install.sh -a

# Sauvegarder les credentials affichés !
# URL: https://<WAZUH-SERVER-IP>
# User: admin
# Password: <generated-password>

# Vérification des services
sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard
```

### 3️⃣ Enrôlement Agent Linux

```bash
# Sur Linux-Client
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.0-1_amd64.deb
sudo WAZUH_MANAGER='<WAZUH-PRIVATE-IP>' dpkg -i ./wazuh-agent_4.7.0-1_amd64.deb

# Démarrage agent
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent

# Vérification
sudo systemctl status wazuh-agent
```

### 4️⃣ Enrôlement Agent Windows

```powershell
# Dans PowerShell (Administrateur) sur Windows-Client
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi -OutFile $env:tmp\wazuh-agent.msi
msiexec.exe /i $env:tmp\wazuh-agent.msi /q WAZUH_MANAGER='<WAZUH-PRIVATE-IP>'

# Démarrage service
NET START WazuhSvc

# Vérification
Get-Service WazuhSvc
```

### 5️⃣ Installation Sysmon (Optionnel - EDR enrichi)

```powershell
# Téléchargement Sysmon
Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile $env:TEMP\Sysmon.zip
Expand-Archive -Path $env:TEMP\Sysmon.zip -DestinationPath $env:TEMP\Sysmon -Force

# Configuration
cd $env:TEMP\Sysmon
Invoke-WebRequest -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile sysmonconfig.xml

# Installation
.\Sysmon64.exe -accepteula -i sysmonconfig.xml

# Configuration Wazuh pour collecter logs Sysmon
# Ajouter dans C:\Program Files (x86)\ossec-agent\ossec.conf :
# <localfile>
#   <location>Microsoft-Windows-Sysmon/Operational</location>
#   <log_format>eventchannel</log_format>
# </localfile>

# Redémarrer agent
NET STOP WazuhSvc
NET START WazuhSvc
```

## 🎭 Scénarios de Démonstration

### Linux - Événements SIEM

#### 1. Brute Force SSH
```bash
# Depuis une machine externe ou localhost
ssh fakeuser@<LINUX-CLIENT-IP>
# Répéter 5-10 fois avec mauvais mot de passe
```

**Résultat attendu:**
- Rule ID: 5710, 5712
- Description: "SSH authentication failed"
- Niveau de sévérité: 5-10

#### 2. Élévation de Privilèges
```bash
sudo su
whoami  # root
exit
```

**Résultat attendu:**
- Rule ID: 5402
- Description: "Successful sudo to ROOT executed"

#### 3. Modification Fichier Sensible (FIM)
```bash
echo "# test" | sudo tee -a /etc/passwd
```

**Résultat attendu:**
- Rule ID: 550, 553
- Description: "Integrity checksum changed"
- Fichier: /etc/passwd

---

### Windows - Événements EDR

#### 1. Échecs Authentification RDP
```
Tentatives de connexion RDP avec mauvais credentials (3-5 fois)
```

**Résultat attendu:**
- Windows Event ID: 4625
- Description: "Windows User Logon Failed"

#### 2. Création Utilisateur Local (IAM)
```powershell
net user labuser P@ssw0rd! /add
net localgroup administrators labuser /add
```

**Résultat attendu:**
- Event ID: 4720 (User created)
- Event ID: 4732 (Added to group)

#### 3. Exécution Processus (Sysmon)
```powershell
notepad.exe
ping google.com
Test-NetConnection google.com -Port 80
```

**Résultat attendu:**
- Sysmon Event ID: 1 (Process creation)
- Sysmon Event ID: 3 (Network connection)
- Détails: CommandLine, ParentImage, Hashes

## 🔍 Threat Hunting - Requêtes Pratiques

### Requête 1: Détection Brute Force
```
rule.groups:"authentication_failed" AND agent.name:"Linux-Client"
```

**Objectif:** Identifier tentatives d'accès non autorisé

**Indicateurs:**
- Plus de 5 échecs en 5 minutes
- Multiples noms d'utilisateur testés
- Patterns temporels réguliers (automatisation)

---

### Requête 2: Activité Privilégiée Suspecte
```
(rule.id:5402 OR data.win.eventdata.eventID:4672) AND NOT user.name:"admin"
```

**Objectif:** Surveiller escalades de privilèges non autorisées

**Indicateurs:**
- Utilisation sudo par utilisateurs non-admin
- Horaires inhabituels (nuit, weekend)
- Commandes sensibles exécutées

---

### Requête 3: Détection Processus Malveillants
```
data.win.system.eventID:1 AND (data.win.eventdata.commandLine:(*powershell* AND *-enc*) OR data.win.eventdata.commandLine:(*certutil*))
```

**Objectif:** Identifier exécution de code encodé ou LOLBins

**Indicateurs:**
- PowerShell avec commandes encodées (-enc)
- Utilisation de certutil, bitsadmin
- Relations parent-child suspectes
- Exécution depuis %TEMP%

## 📊 Visualisation Dashboard

### Accès Dashboard
```
URL: https://<WAZUH-SERVER-IP>
User: admin
Password: <your-generated-password>
```

### Navigation Principale

**Modules → Security Events:**
- Vue temps réel des alertes
- Filtres par agent, règle, sévérité
- Analyse temporelle

**Modules → Integrity Monitoring:**
- Fichiers modifiés
- Changements non autorisés

**Modules → Security Configuration Assessment:**
- Audit de configuration
- Compliance checks

**Threat Hunting:**
- Requêtes personnalisées
- Recherche d'IOCs
- Investigation forensique

## 📚 Concepts Clés

### SIEM vs EDR

| Aspect | SIEM | EDR |
|--------|------|-----|
| **Focus** | Logs centralisés, corrélation multi-sources | Activité endpoint, comportement processus |
| **Visibilité** | Large (réseau, systèmes, applications) | Profonde (processus, fichiers, registre) |
| **Détection** | Règles, patterns, anomalies statistiques | Comportemental, IOCs, ML |
| **Cas d'usage** | Compliance, audit, vue globale SOC | Threat hunting, investigation, réponse incidents |
| **Données** | Logs textuels | Télémétrie riche (hashes, command lines) |

**Wazuh = SIEM + EDR intégré**

### IAM/PAM Monitoring

**Identity and Access Management (IAM):**
- Suivi authentifications (succès/échecs)
- Gestion cycle de vie comptes
- Détection anomalies identité

**Privileged Access Management (PAM):**
- Surveillance comptes à privilèges
- Audit utilisation sudo/admin
- Détection escalade privilèges

**Événements surveillés:**
- Windows: 4720, 4722, 4724, 4732, 4625, 4672
- Linux: auth.log (sudo, su, SSH)

## 🛠️ Fichiers de Configuration

### ossec.conf (Agent Linux)
```xml
<ossec_config>
  <client>
    <server>
      <address>WAZUH_MANAGER_IP</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
  </client>
  
  <syscheck>
    <directories check_all="yes">/etc,/usr/bin,/usr/sbin</directories>
    <directories check_all="yes">/bin,/sbin</directories>
  </syscheck>
</ossec_config>
```

### ossec.conf (Agent Windows + Sysmon)
```xml
<ossec_config>
  <client>
    <server>
      <address>WAZUH_MANAGER_IP</address>
    </server>
  </client>
  
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
  
  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
  </localfile>
</ossec_config>
```

## 📸 Captures d'Écran

### Dashboard - Agents Actifs
![Agents Overview](./screenshots/AGENT%20ACTIVE%202.png)

### Alertes Linux - SSH Brute Force
![SSH Alerts](./screenshots/SSH%20Brute%20Force%20Attack%20terminal.png)

### Alertes Windows - Création Utilisateur
![User Creation](./screenshots/SSH%20failed%20authentication.png)

### Sysmon - Process Creation
![Sysmon Events](./screenshots/Sysmon%20events.png)

## 🎓 Compétences Acquises

- ✅ Déploiement infrastructure cloud sécurisée (AWS)
- ✅ Configuration SIEM/EDR (Wazuh)
- ✅ Supervision multi-OS (Linux + Windows)
- ✅ Génération et analyse événements sécurité
- ✅ Threat hunting et requêtes de recherche
- ✅ Understanding IAM/PAM concepts
- ✅ File Integrity Monitoring (FIM)
- ✅ EDR avec Sysmon
- ✅ Analyse de logs et corrélation d'événements

## 🔗 Ressources Externes

- [Wazuh Documentation Officielle](https://documentation.wazuh.com)
- [AWS Learner Lab Guide](https://awsacademy.instructure.com)
- [Sysmon Configuration Reference](https://github.com/SwiftOnSecurity/sysmon-config)
- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [Security Onion - SIEM Alternative](https://securityonionsolutions.com)

## 👨‍🎓 Informations Projet

**Étudiant:** Yasser Namez
**Encadrant:** Prof. Azeddine KHIAT  
**Filière:** II-CCN 
**Année Universitaire:** 2025/2026  
**Établissement:** ENSETM

