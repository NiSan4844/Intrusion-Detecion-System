# Network Intrusion Detection System (NIDS)

> **Disclaimer**: The information and alerts described in this document are intended for educational purposes only and are conducted in a controlled testing environment. Unauthorized access to computer systems and networks is illegal. Always ensure you have permission before conducting any security testing or analysis.

## Table of Contents

1. [Overview](#overview)
2. [Alerts Description](#alerts-description)
   - [1. ICMP Ping Alert](#1-icmp-ping-alert)
   - [2. Port Scan Alert](#2-port-scan-alert)
   - [3. Brute Force SSH Login Alert](#3-brute-force-ssh-login-alert)
   - [4. HTTP GET Flood (DDoS)](#4-http-get-flood-ddos)
   - [5. Malicious File Download Alert](#5-malicious-file-download-alert)
   - [6. C2 Communication Alert](#6-c2-communication-alert)
3. [Conclusion](#conclusion)
4. [Additional Recommendations](#additional-recommendations)

## Overview

This document provides comprehensive descriptions of specific Suricata alerts designed to detect various network attacks. Suricata is an open-source intrusion detection and prevention system (IDS/IPS) that monitors network traffic and raises alerts based on predefined criteria. By understanding these alerts, security professionals can better safeguard their networks and respond to potential threats effectively.

## Alerts Description

### 1. ICMP Ping Alert

-**Rule**:
  ```plaintext
alert icmp any any -> any any (msg:"ICMP Ping Request Detected"; itype:8; sid:1000001; rev:1;)

  ```

- **Attack Description**: 
  An ICMP (Internet Control Message Protocol) ping attack is a basic network reconnaissance technique used to determine if a host is active and reachable on the network. Attackers may use ping requests to discover live hosts, often using tools like ping or fping. While legitimate network administrators use pings for troubleshooting connectivity issues, excessive or unauthorized ping requests may signal malicious intent, such as a precursor to a denial-of-service (DoS) attack.

- **Alert Trigger**: 
  This rule triggers when an ICMP packet with an itype of 8 (which indicates an echo request) is detected. The rule monitors all incoming and outgoing ICMP traffic, and if any host sends an ICMP echo request to any destination, the alert is generated, indicating a potential ping flood or reconnaissance attempt.

---

![ICMP PIng ](https://github.com/user-attachments/assets/27035d23-6ab0-4835-9792-a18cc407e684)

### 2. Port Scan Alert

-**Rule**:

  ```plaintext
alert tcp any any -> any any (msg:"Possible Port Scan Detected"; flags:S; threshold: type both, track by_src, count 20, seconds 10; sid:1000002; rev:1;)

  ```

- **Attack Description**: 
  A port scan is a technique used by attackers to discover open ports and services running on a target system. By sending connection requests to multiple ports, an attacker gathers information that could lead to further exploitation. Various tools, such as Nmap and Netcat, can automate this process. Port scans can be classified as active (sending packets) or passive (analyzing responses), and can often be a precursor to more serious attacks.

- **Alert Trigger**: 
  This rule is triggered when a source IP address sends SYN packets (indicative of connection initiation) to multiple destination ports. If 20 SYN packets are detected from the same source within a 10-second window, the rule activates, indicating a potential port scan attempt. The use of the threshold option helps reduce false positives by requiring multiple attempts from the same source.

---

![port scan](https://github.com/user-attachments/assets/4b0654a4-3bc6-4792-a690-ce3e6a9edebe)

![Port scan](https://github.com/user-attachments/assets/8070d08b-b1d4-4525-b5e9-bfb5627f57d3)

### 3. Brute Force SSH Login Alert

  ```plaintext
alert tcp any any -> any 22 (msg:"SSH Brute Force Attempt"; flow:established,to_server; content:"SSH"; detection_filter:track by_dst, count 5, seconds 60; sid:1000003; rev:1;)

  ```

- **Attack Description**: 
  A brute force SSH login attack involves an attacker repeatedly attempting to gain unauthorized access to an SSH server by systematically trying different username and password combinations. Automated tools, such as Hydra or Medusa, can make these attempts at a high rate, which can lead to successful unauthorized access if weak credentials are used. Brute force attacks are often stealthy and may go unnoticed without proper detection mechanisms.

- **Alert Trigger**: 
  This rule triggers when a specific destination (the SSH server) receives five or more SSH connection attempts from the same source IP within 60 seconds. The flow: established,to_server condition ensures that the rule only applies to established connections that are actively targeting the SSH service (port 22). This helps identify potential brute force attacks while filtering out legitimate login attempts.

---

![bruteforce ssh login](https://github.com/user-attachments/assets/b6aa6b7a-7f3e-4fda-a04e-7f37cfaf4379)

![Brute force ssh](https://github.com/user-attachments/assets/b4e67e6f-2ae8-4407-a35f-e5d6c58f9e47)

### 4. HTTP GET Flood (DDoS)

  ```plaintext
alert http any any -> any any (msg:"HTTP GET Flood Detected"; threshold:type threshold, track by_src, count 100, seconds 1; content:"GET"; http_method; classtype:attempted-dos; sid:1000004; rev:1;)

  ```

- **Attack Description**: 
  An HTTP GET flood is a type of Distributed Denial-of-Service (DDoS) attack in which an attacker overwhelms a web server by sending a high volume of HTTP GET requests in a short time frame. This surge in traffic can exhaust server resources, preventing it from responding to legitimate user requests, and can lead to service degradation or complete downtime. Attackers may employ botnets or automated scripts to facilitate these floods.

- **Alert Trigger**: 
  This rule is triggered when a single source IP sends 100 or more HTTP GET requests within a one-second window. The use of threshold and track by_src allows for detection of rapid request bursts that indicate potential DDoS activity. The content:"GET" condition specifies that the alert is looking specifically for HTTP GET requests.
---

![HTTP GET flood](https://github.com/user-attachments/assets/2085bb77-ec99-49cd-93f8-f150a9340135)

![HTTP GET flood](https://github.com/user-attachments/assets/a04e3e58-9a9b-49f7-8a77-3fe040712b70)

### 5. Malicious File Download Alert

  ```plaintext
alert http any any -> any any (msg:"Potential Malicious File Download"; flow:to_server,established; content:"malware.txt"; http_uri; nocase; classtype:trojan-activity; sid:1000005; rev:1;)

  ```

- **Attack Description**: 
  Malicious file downloads occur when an attacker attempts to deliver harmful files (such as malware or viruses) to a target system via HTTP. This often involves social engineering techniques to persuade users to download these files, which can lead to system compromise. Common methods include phishing emails with malicious attachments or links that lead to the download of harmful files.

- **Alert Trigger**: 
  This rule triggers when an HTTP request is made to download a file with the URI containing "malware.txt". The flow:to_server,established condition ensures the alert only triggers for established connections where a file is being sent to the server, suggesting a potentially malicious download attempt. The nocase option makes the search case-insensitive, allowing for broader detection.

---

![Malicious file download from attacker ip](https://github.com/user-attachments/assets/1ea614ef-9178-42d6-91b0-5c68ea0983f4)


![malicious file downlaod](https://github.com/user-attachments/assets/92006fea-fd38-42d7-b6c1-edcb89d5cbc1)

### 6. C2 Communication Alert


  ```plaintext
alert tcp any any -> 10.0.2.4 9999 (msg:"C2 Communication Detected"; flow:established; classtype:trojan-activity; sid:1000007; rev:1;)

  ```

- **Attack Description**: 
   Command and Control (C2) communication refers to a mechanism used by attackers to remotely control compromised systems. Once a system is infected with malware, it may connect to a C2 server to receive commands or exfiltrate data. Detecting C2 communication is critical for identifying ongoing breaches and mitigating further damage. These connections often occur over specific ports and to known malicious IP addresses.

- **Alert Trigger**: 
  This rule triggers when any TCP traffic is detected directed to the specific IP address (10.0.2.4) on port 9999. The flow:established condition ensures that the alert only triggers for established connections, indicating that a compromised host is actively communicating with a potentially malicious server. This behavior is characteristic of C2 communication and may require immediate investigation.

---

![c2_server comm](https://github.com/user-attachments/assets/0c3502cc-ea0e-46e2-9c35-8714734768be)

![c2_server_comm](https://github.com/user-attachments/assets/5682c466-1258-41a5-8267-305bf7f086b6)

![c2_comm_detected](https://github.com/user-attachments/assets/ead5d28c-3f2d-4474-88c5-fbd899cf0915)

## Conclusion

The above alerts are essential for monitoring and protecting network environments against various types of attacks. By implementing these alerts, security teams can enhance their ability to detect and respond to potential threats effectively. Regularly reviewing and updating detection criteria is crucial for maintaining security posture in the ever-evolving threat landscape.

![Rules](https://github.com/user-attachments/assets/c7f0c9f3-5d89-4f5d-b14c-faf4e14372f3)

## Additional Recommendations

- **Regular Updates**: Keep Suricata and its alerts updated to ensure coverage against new threats.
- **Monitoring and Response**: Implement continuous monitoring to respond swiftly to alerts generated by these systems.
- **Logging and Analysis**: Maintain logs for all alerts and analyze them periodically to identify trends and improve detection capabilities.
