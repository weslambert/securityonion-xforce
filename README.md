# securityonion-xforce

### Overview

Pull down [IBM X-Force Threat Exchange](https://exchange.xforce.ibmcloud.com/) IP and Domain data and use it with the Zeek (Bro) Intel Framework in [Security Onion](https://securityonion.net).

By default, the first `100` results for each category (respective to the URL/Domain indicator types) for the last 90 days are returned and populated in `/opt/bro/share/bro/policy/bro-xforce/xforce.dat`.  This value can be changed by editing the `results_limit` value in `/opt/bro/share/bro/policy/bro-xforce/bro-xforce.conf`  

The default categories to search through include:

- Anonymization Services
- Bots
- Botnet Command and Control Server
- Computer Crime / Hacking
- Dynamic IPs
- Malware
- Phishing URLs

Categories can be removed/added in `/opt/bro/share/bro/policy/bro-xforce/bro-xforce.conf`.

The majority of this effort is heavily based on the great work Stephen Hosom has already done in his [Alienvault OTX Connector for Bro](https://github.com/hosom/bro-otx) (also adapted for Security Onion [here](https://github.com/weslambert/securityonion-otx)).

### Prerequisites:

- X-Force Threat Exchange API Key/Password (Commercial API - Free 30-day trial available)

### Install:

`wget https://raw.githubusercontent.com/weslambert/securityonion-xforce/master/securityonion-xforce && chmod +x securityonion-xforce && sudo ./securityonion-xforce` 

