### SMB PORT SCANNING
SMB (Server Message Block) Port Scanning is a reconnaissance activity performed to determine whether devices on a network are utilizing the SMB protocol and to identify which specific ports (primarily TCP 445, and occasionally UDP/TCP 137, 138, 139) are exposed externally.

This is often one of the primary areas of focus for both attackers and defenders (Blue Team) in network security. Because of its design, SMB handles highly critical operations while historically having been susceptible to significant vulnerabilities

# A. Attack Phase
As demonstrated below, a port scan is performed against the target IP address using the Nmap tool:

```
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sS -p 440-450 192.168.56.1
[sudo] password for kali: 
Starting Nmap 7.98 ( https://nmap.org ) at 2026-06-20 05:00 -0400
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 192.168.56.1
Host is up (0.00096s latency).

PORT    STATE    SERVICE
440/tcp filtered sgcp
441/tcp filtered decvms-sysmgt
442/tcp filtered cvc_hostd
443/tcp filtered https
444/tcp filtered snpp
445/tcp open     microsoft-ds
446/tcp filtered ddm-rdb
447/tcp filtered ddm-dfm
448/tcp filtered ddm-ssl
449/tcp filtered as-servermap
450/tcp filtered tserver
MAC Address: 0A:00:27:00:00:0E (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 1.53 seconds
```

# B. Suricata Rule Writing
This Suricata rule generates an alert for a potential reconnaissance attempt by capturing TCP packets originating from any source, destined for SMB port 445, where only the SYN flag (connection request) is set:

```
alert tcp any any -> any 445 (msg:"Kali SMB Port Tarama"; flags:S; classtype:attempted-recon; sid:200002; rev:3;)
```

# C. Post-Attack Suricata Log Verification Phase
We can verify that our custom rule has successfully generated a log entry by inspecting Suricata's eve.json file:

![Suricata Log](../screenshots/smb-log-1.png?v=2)


# D. Alerting Phase (React Dashboard + Telegram Bot)
Finally, we pass the generated alerts into our custom dashboard or a designated Telegram bot chat, converting them into real-time notifications for quicker visibility.

![Suricata Alert](../screenshots/smb-log-2.png?v=2)
![Suricata Alert](../screenshots/smb-log-3.jpg?v=2)
