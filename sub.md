<style>
H1{color:purple;}
H3{color:black;}
H4{color:mediumpurple;}
H5{color:magenta;}
</style>


# Frameworks (to keep in mind)


### Pyramid of Pain  

##### [1 = barely annoying, 7 = the most annoying]  

1. Hash  
- File identity, easily changed by any edits to file's source  
2. IPs  
- User/location identity, can be changed  
3. Domain Names  
- Hosting identity, can be changed, more annoying  
4. Host Artifacts  
- Leftover file changes, processes, binary changes, deletions, etc  
5. Network Artifacts  
- Leftover HTTP requests, anomaly user-agent connections, URI requests/patterns  
6. Tools  
- Payload identity, file signatures, detection rules, identify procedure of tools, use OSINT to under how to detect behavior  
7. TTPs  
- Identify step-by-step procedures related to tactics / tooling and detect such behaviors using logging/monitoring tools. Most Annoying.  

### Cyber Kill Chain

#### Recon > Weaponization > Delivery > Exploitation > Installation > Command & Control (C2) > Exfiltration (Actions on Objectives)  

1. Recon  
- OSINT (public info, leaked, darkweb)
- Harvest identity (email, usernames, passwords)
- Social media
- IPs, URLs, domains  

2. Weaponization  
- "Inside the trojan horse"
- Malware (overall malicious software)
- Exploits (breaking through security/vulnerability function - connecting through/logging in/installing)
- Payload (executing function)  

3. Delivery  
- Phishing for clicks
- Infected USB / files / file sharing
- Malicious URLs / Web apps / spoofed domains  

4. Exploitation  
- After initial access (authorized into victim system)
	+ Exploit software, firmware, hardware
	+ Code exploits -> human vulnerabilities
	+ Trigger server-based vulnerabilities  

5. Installation    
- Install a solution to reaccess the system if initial connection/access lost
- Backdoor, web shell script, masquerade payload into OS/software

6. Command & Control (C2)    
- Send ("Beacon") network traffic from victim machine to attacker's machine for commands  
- Establish control victim's machine from beaconing responses  
- DNS requests, HTTP requests  


7. Exfiltration (Actions on Objectives)    
- With control established, act on attacker's objectives for hacking this system  
- Collect credentials  
- Escalate privs  
- More recon  
- Lateral movement through network enviornment  
- Corrupt/overwrite/exfiltrate/delete data    

### Unified Kill Chain  

* Modernized Kill Chain framework (compared to MITRE and others)
* 18 phases
* Realistic
	- Recon phase may happen after initial access
	- Phases may reoccur
* Covers entire attack from motivation to objectives  

![imageHere](https://i.imgur.com/AH9euRs.png)  

```
Reconnaissance (MITRE TA0043)  
Weaponization (MITRE TA0001)  
Social Engineering (MITRE TA0001)  
Exploitation (MITRE TA0002)  
Persistence (MITRE TA0003)  
Defense Evasion (MITRE TA0005)  
Command & Control (MITRE TA0011)  
Pivoting (MITRE TA0008)  

```

### Diamond Model

#### Event Meta Features  
We can, if possible, attribute certain meta information to enrich threat intelligence for events caused by adversaries/attacks such as:

* Timestamp
* Phase (kill chain)
* Result (event result)
* Direction (victim-to-infra, infra-to-victim, infra-to-infra, adversary-to-infra, etc)
* Methodology (phishing, DDoS, network scanning, etc)
* Resources (software, knowledge, osint, ransom, hardware, privs/auth, etc)


# Detection Engineering

### Approach to Detections

1. Attack vector / MITRE classifcation / kill chain
	- Theorize the attack
	- IOC possibilities
	- Consider which logs
2. Logs
	- Visibility
	- Field selection
3. Filter clause to detection behavior
	- "where"
	- where Filter1 and/or Filter2
	- where Filter1 or (Filter2 and Filter3)
	- etc
3. Baseline activity
	- Goal: Narrow/remove false positive alerting
	- What is reasonable
	- IP addresses
	- Commands
	- Devices / Hosts / Servers
	- Quantity of action
	- Identity privilege related to user and action
4. 

### Log Sources

1. Identity
	- (A)AD, Sysmon, AWS
	- App suites, Okta, etc
	- Cloud App sign-ins
	- Cloud Resource sign-ins
	- Company worker logs 
2. Authorization  
	- Okta
	- Azure, AWS
	- VPN
	- Device
	- App logs
3. Network
	- Auth + Identity logs
	- VPN
	- Device
	- Windows / Linux / OS logs
	- IDS / EDR logs  
	
#### Correlating log sources

This is important af!


# OSINT  

### Website Searching

#### Files/Hashes
- [VirusTotal](https://www.virustotal.com/)    
- MetaDefender  

#### Domain
- URLScan  
- RiskIQ
- WhoIs

#### Email
- MXToolbox  

# Questions  

* Kafka
* Samza
* Kafka vs Samza
* Syslog 
* Syslog vs Kafka
* REST API
* Serverless data pipelines
* 
