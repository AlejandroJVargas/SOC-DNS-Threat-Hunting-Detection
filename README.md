# SOC-DNS-Threat-Hunting-Detection
SOC Threat Hunting lab using Splunk to analyze Zeek DNS logs. Focuses on detecting C2 beaconing, DNS tunneling (data exfiltration), and DGA/brute-force anomalies via SPL

# SOC Investigation & Threat Hunting: DNS Anomaly & Exfiltration Analysis

## 1. Executive Summary
During proactive threat hunting operations, an investigation was conducted on **422,130+ Zeek/Bro DNS transaction logs** indexed within **Splunk Enterprise**. The primary objective was to detect covert channels, command-and-control (C2) beaconing, data exfiltration via DNS tunneling, and suspicious domain resolution behaviors across the internal network segment.

---

## 2. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Details |
| :--- | :--- | :--- | :--- |
| **Command and Control** | `T1071.004` | Application Layer Protocol: DNS | Identifying covert communication channels over Port 53/UDP. |
| **Exfiltration** | `T1048.003` | Exfiltration Over Alternative Protocol | Analysis of high-entropy / long subdomains used for data staging. |
| **Reconnaissance** | `T1590.002` | Gather Victim Network Information: DNS | Domain name resolution scanning and DGA analysis. |

---

## 3. Investigation & Threat Hunting (SPL Queries)

### 3.1. Identifying Top DNS Consumers (Potential C2 Beaconing)
```spl
sourcetype="zeek_dns" NOT "#*"
| rex "^(?<ts>[^\t\s]+)\s+(?<uid>[^\t\s]+)\s+(?<src_ip>[^\t\s]+)\s+(?<src_port>[^\t\s]+)\s+(?<dest_ip>[^\t\s]+)\s+(?<dest_port>[^\t\s]+)\s+(?<proto>[^\t\s]+)\s+(?<trans_id>[^\t\s]+)\s+(?<query>[^\t\s]+)"
| stats count by src_ip
| sort - count
```

**Findings:** The host **10.10.117.210** generated an anomalous volume of DNS requests (**75,943 queries**). This disproportionate frequency strongly indicates potential C2 beaconing or automated network scanning behavior.

---

### 3.2 Identifying Top Domain With Anomaly Frequency (Spikes/Beaconing) 
```spl
sourcetype="zeek_dns" NOT "#*"
| rex "^(?<ts>[^\t\s]+)\s+(?<uid>[^\t\s]+)\s+(?<src_ip>[^\t\s]+)\s+(?<src_port>[^\t\s]+)\s+(?<dest_ip>[^\t\s]+)\s+(?<dest_port>[^\t\s]+)\s+(?<proto>[^\t\s]+)\s+(?<trans_id>[^\t\s]+)\s+(?<query>[^\t\s]+)"
| top limit=20 query, src_ip
```

**Findings:** The host **10.10.117.210** and the queried the domain **teredo.ipv6.microsoft.com** generated an anomalous number of times (**27.425 requests**). While Teredo is a known Microsoft IPv6 tunneling protocol that often generates noisy telemetry, this disproportionate volume mimics C2 beaconing behavior and requires further investigation to rule out potential abuse or tunneling over legitimate services.

---

### 3.3 Identifying DNS Tunneling (Query length)
```spl
sourcetype="zeek_dns" NOT "#*"
| rex "^(?<ts>[^\t\s]+)\s+(?<uid>[^\t\s]+)\s+(?<src_ip>[^\t\s]+)\s+(?<src_port>[^\t\s]+)\s+(?<dest_ip>[^\t\s]+)\s+(?<dest_port>[^\t\s]+)\s+(?<proto>[^\t\s]+)\s+(?<trans_id>[^\t\s]+)\s+(?<query>[^\t\s]+)"
| eval query_length=len(query)
| where query_length > 25
| table src_ip, dest_ip, query, query_length
| sort - query_length
```
**Findings:** The host **192.168.207.4** generated anomalous DNS requests to the domain **0050430195e1** with an excessive length of  (**12 characters**). High-entropy, oversized DNS queries like this deviate significantly from baseline traffic and are highly indicative of data exfiltration or Command & Control (C2) communication via DNS tunneling techniques.

---

### 3.4 Identifying Brute Force (NXDOMAIN)
```spl
sourcetype="zeek_dns" "NXDOMAIN" NOT "#*"
| rex "^(?<ts>[^\t\s]+)\s+(?<uid>[^\t\s]+)\s+(?<src_ip>[^\t\s]+)\s+(?<src_port>[^\t\s]+)\s+(?<dest_ip>[^\t\s]+)\s+(?<dest_port>[^\t\s]+)\s+(?<proto>[^\t\s]+)\s+(?<trans_id>[^\t\s]+)\s+(?<query>[^\t\s]+)\s+(?<qclass>[^\t\s]+)\s+(?<qclass_name>[^\t\s]+)\s+(?<qtype>[^\t\s]+)\s+(?<qtype_name>[^\t\s]+)\s+(?<rcode>[^\t\s]+)\s+(?<rcode_name>[^\t\s]+)"
| stats count by src_ip, query
| sort - count
```

**Findings:** The host **192.168.202.83** generated a high volume of NXDOMAIN errors (**4,146 failures**) when querying (**44.206.168.192.in-addr.arpa**). A massive amount of reverse DNS lookups failing indicates that this machine is likely performing active internal network scanning (Reconnaissance) to map other hosts.

---

### 3.5 Identifying Potential DNS Exfiltration
```spl
sourcetype="zeek_dns" "NXDOMAIN" NOT "#*"
| rex "^(?<ts>[^\t\s]+)\s+(?<uid>[^\t\s]+)\s+(?<src_ip>[^\t\s]+)\s+(?<src_port>[^\t\s]+)\s+(?<dest_ip>[^\t\s]+)\s+(?<dest_port>[^\t\s]+)\s+(?<proto>[^\t\s]+)\s+(?<trans_id>[^\t\s]+)\s+(?<query>[^\t\s]+)"
| eval query_length=len(query)
| where query_length > 50
| stats count by src_ip, query, query_length
| where count > 10
```

**Findings:** The host **192.168.202.140** generated queries with a length of (**51 characters**) targeting (**versioncheck.addons.mozilla.org.hsd1.md.comcast.net**) (16 times). While the query length triggers the exfiltration rule, investigation reveals this is a False Positive. The traffic consists of a legitimate Mozilla Firefox update check that failed and was subsequently appended with the local ISP DNS search suffix (Comcast). This highlights the importance of tuning SIEM detection rules to whitelist known local search domains.

**Full Incident Report:** [View PDF Document](docs/incident_response.pdf)
