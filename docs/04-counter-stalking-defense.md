# Counter-Surveillance (Defensive)

> **Status — Conceptual research architecture.** This part is a design exploration. Nothing described here has been built, tested, validated, or deployed, and technical terminology is not evidence that any inference is empirically established.
>
> **Scope — Defensive security.** The techniques in this part are framed exclusively as *defensive* countermeasures — abuse prevention and counter-surveillance for people being stalked, harassed, or targeted. Anything that reads as offensive (traps, decoys, active probing) is presented as a defense against an adversary who is already surveilling or attacking the operator. Any real deployment requires legal review (see the legal analysis in Part 04).

---

## Part I: Exploiting TA0043 – Reconnaissance (Setting the Traps)
The stalker must look at you to track you. Every time they look, they risk leaving a footprint. Your goal here is to plant "canary tokens" and deceptive data points that force their system to call home to a server you control.
### Step 1: Active Document Trapping (T1589 – Gather Victim Identity Info)
* The Concept: The stalker will search for your name, historical records, or professional PDFs. You will intentionally leak a "bait" document that phones home when opened.
* The Execution:
   1. Embed a hidden, single-pixel image tracking URL (a web beacon) into a PDF or Word document containing ostensibly private data (e.g., a file titled Personal\_History\_Archive.pdf or Michigan\_Property\_Records.pdf).
   2. Host this file on a public-facing directory or a personal site that is easily discoverable via targeted searches.
   3. When the stalker downloads and opens the document, their local application (like Adobe Reader or Word) will attempt to render the image, forcing an outbound connection to your logging server.
* The Capture: You instantly collect the stalker’s true public IP address, their Internet Service Provider (ISP), exact UTC timestamps, and their application User-Agent string.
### Step 2: Web Surface Honey-Potting (T1594 – Search Open Technical Registers)
* The Concept: Stalkers regularly audit your public profiles or websites looking for changes or updates.
* The Execution:
   1. Deploy a basic personal portfolio page or static landing page under a domain variant closely tied to your name.
   2. Configure the backend web server (Nginx or Apache) to run deep logging on connection headers, specifically capturing HTTP/2 stream settings, TLS handshakes, and header sequencing.
   3. Restrict public indexation or keep the link obscure. Anyone who finds and repeatedly visits this site is actively hunting for your specific digital footprint.
* The Capture: You build a baseline profile of their browser environment, identifying if they are using standard consumer devices or automated scraping tools (like custom Python scripts).
## Part II: Exploiting TA0042 – Resource Development (Tracking Their Tools)
To scale their harassment or tracking, a persistent stalker must acquire infrastructure—buying domains, spinning up virtual private servers (VPS), or renting cheap commercial VPNs to hide their location.
```text
[Stalker Infrastructure] ──► Purchases Domain / Staging VPS (TA0042)
                                      │
                                      ▼
[Your Defensive Pipeline] ──► Passive DNS & Certificate Log Scraping (TA0043)
                                      │
                                      ▼
                        [Identity Grouping & Fingerprint Match]
```

### Step 3: Passive DNS and SSL/TLS Monitoring (T1583 – Acquire Infrastructure)
* The Concept: If a stalker sets up a lookalike domain to phish you, impersonate your close circles, or host an infrastructure point, they must generate an SSL/TLS certificate to secure the connection.
* The Execution:
   1. Set up an automated monitoring script to continuously scrape public Certificate Transparency (CT) logs via services like crt.sh or a Python monitoring script.
   2. Set the watch parameters to alert on any newly registered domains containing variations of your name, family names, or custom project terms.
* The Capture: You identify the exact moment the stalker registers a hostile asset, giving you early warning before they launch an interaction or attack.
### Step 4: Infrastructure Verification and Disambiguation (T1584 – Compromise/Abuse Infrastructure)
* The Concept: The stalker will route their tracking attempts or automated scans through legitimate cloud services (AWS EC2, GitHub Actions, or commercial VPN nodes) to avoid direct blocklists.
* The Execution:
   1. When an anomalous IP hits your honey-pot or tracking tokens, immediately cross-reference it against the dynamic public IP feeds of cloud providers (like the JSON files provided by AWS and Azure).
   2. Extract the underlying transport layer fingerprint (JA4 or JA3), matching the TLS Client Hello parameters.
* The Capture: If the stalker switches their IP address from an AWS node to a commercial VPN node, but their automated tool sends the exact same JA4 hash string, the pipeline groups both events into a single profile. The IP rotation becomes completely useless to them.
## Part III: The Counter-Stalking Dashboard Matrix
By organizing these tracking hooks, your analytics pipeline transitions from passive defense to an active counter-surveillance apparatus:
| Attack Phase | Adversary Objective | Counter-Surveillance Trap | Derived Intel (What You Win) |
|---|---|---|---|
| TA0043 / T1589 | Gather private history or files. | Canary token embedded in leaked "bait" archives. | True egress IP, network operator, and timestamp of file execution. |
| TA0043 / T1590 | Monitor your digital footprint. | Custom web honey-pot with raw header logging enabled. | Browser engine signatures, OS kernel traits (p0f), and scraping frequency. |
| TA0042 / T1583 | Build infrastructure to target you. | Automated Certificate Transparency log tracking. | Lookalike domains, hosting providers, and operational launch times. |
## Part IV: Turning Intel into Defensive Action
Once the pipeline labels the adversary's technical fingerprint:
1. Do Not Alert the Target: Avoid performing active scanning or aggressive probing back against their infrastructure, as this alerts them that their OPSEC has collapsed and prompts them to switch tools.
2. Deploy Selective Dropping: If they are using automated scripts to monitor you, configure your reverse proxy or web application firewall to respond to their specific JA4 fingerprint with a 404 Not Found or a static, fake page. This starves them of real information while keeping them trapped in a dead simulation loop.
3. Compile the Legal/Abuse Packet: Package the extracted network logs, verified UTC timestamps, and cloud provider IP assignments. Submit a clean, technical abuse report to the cloud provider's risk team (e.g., Amazon or GitHub Abuse) to permanently decommission their staging infrastructure.

```python
import urllib.request
import time

def verify_environment():
    # A completely benign-looking function that purports to check API connectivity
    # Replace the URL with your unique logging subdomain or Canary Token endpoint
    telemetry_url = "http://verification.yourdomain.com/log?t=" + str(time.time())
    try:
        req = urllib.request.Request(
            telemetry_url,
            headers={'User-Agent': 'System-Environment-Validator/1.0'}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            pass
    except Exception:
        pass # Fail silently so the stalker suspects nothing

verify_environment()
```

* * *   **The Trap:** When the stalker clones or downloads the 50 pages of code to their local machine and runs the setup script to audit or execute it, their local machine performs an unproxied DNS lookup and HTTP connection straight to your listener.

### 2. The Document Web Beacon Route (PDF/Docx)
If the 50 pages of code are packaged as a reading document (like a PDF file) rather than raw scripts, you can leverage native application rendering behaviors to force an outbound callback.

*   **The Mechanism:** Modern document viewers (Adobe Acrobat, Microsoft Word) follow strict parsing rules for linked remote assets. You can inject a hidden, single-pixel hyperlinked image or a dynamic XML schema link into the body of the file.
*   **The Implementation via CanaryTokens:**
    1. Utilize a trusted metadata tracking generator like **CanaryTokens.org** to generate a unique MS Word or Adobe Acrobat tracking file.
    2. Merge your 50 pages of code directly into that structured file layout.
    3. Upload the finalized PDF/Docx archive to your Google Drive.
*   **The Trap:** Google Drive will show a safe, static preview of the document. But the moment the stalker clicks **Download** to pore through all 50 pages locally, their local PDF reader or Word application will instantly parse the document structure, execute the remote asset call, and drop their true network signature right into your alerting pipeline.

---

## What Telemetry You Can Actually Extract

Once the stalker’s local machine fires the outbound call to your logging endpoint (e.g., a lightweight cloud VPS or a managed CanaryTokens listener), you circumvent Google's protection entirely and collect the following indicators:

*   **True Egress IP & ISP:** You bypass the Google proxy. If they are using a commercial VPN, you capture the specific exit node IP and the name of the VPN provider (e.g., NordVPN, Mullvad).
*   **Transport Layer Fingerprint (JA4/JA3):** If they ran your Python/Bash setup script, you capture the specific cryptographic signature of their local command-line runtime environment, allowing you to track them even if they cycle their VPN location.
*   **Network Jitter Metric ($J$):** By inspecting successive packet arrival gaps on your listening server during the connection handshake, you can estimate network latency variations, helping profile the structural stability of their internet connection.

---

## Defensive OPSEC Warning

When configuring this trap on Google Drive, pay strict attention to **your own privacy boundaries**:

1.  **Check File Ownership:** Ensure that the Google account hosting the shared link does not display your real name, email address, or recognizable handle in the file's "Owner" or "Details" column. Use an completely burner, isolated Google profile to generate the public share link.
2.  **Set Explicit Sharing Permissions:** Set the access control link to *"Anyone with the link can view"

## The Legal Foundation: What Works in Your Favor
Under United States federal law, specifically the Computer Fraud and Abuse Act (CFAA) (18 U.S.C. § 1030), civil or criminal liability typically hinges on accessing a computer "without authorization" or "exceeding authorized access."
## The "Consent via Interaction" Principle
When you place a file on Google Drive and set it to public or share a link, you are publishing content that you own.
* If a third party clicks your link, downloads your file, and runs your script on their own machine, they are authorizing the execution of that data on their own endpoint.
* They are using their data, their electricity, and their processor to run code you provided. Because you did not break into their machine to implant a listener, you generally have not committed an unauthorized access violation under the CFAA. You simply hosted an asset that they chose to open.
## The Analogy of the Visible License Plate
Capturing an IP address, ISP, or a user-agent string is legally treated similarly to recording a license plate on a car driving past your house.
The Baseline: Courts generally rule that an IP address is a public-facing routing identifier rather than deeply protected private data, because it must be broadcast to the network to request the data in the first place. You are logging traffic hitting your own listener.
## 2. Where the "Gray Area" Turns Dark (The Risks)
While the act of logging an inbound connection is highly defensible, the implementation details can cross legal lines quickly depending on how you structure the trap.
## Risk A: Deceptive Content & Entrapment Claims
If your 50 pages of code or documents use copyrighted material, trade secrets belonging to a third party, or masquerade as a specific entity to trick the stalker into opening it, you open yourself up to civil liability regarding intellectual property or fraud. The file must remain fundamentally yours to claim absolute authorization over its distribution.
## Risk B: Exceeding Simple Telemetry (Active Countermeasures)
There is a massive statutory distinction between Passive Logging and Active Retaliation.
* Safe: Tracking an IP address, ISP, or jitter via a standard DNS/HTTP callback. This is standard diagnostic behavior used by corporations globally (frequently called "Canary Tokens" or "Honeytokens") to detect insider threats or data leaks.
* Illegal: If your script does anything to alter, extract, or damage the target machine (e.g., executing a command to copy their local browser cookies, scanning their internal home network, or downloading files from their desktop back to you). The moment your code pulls data from their machine that wasn't part of the standard HTTP network handshake, you have crossed from a defensive trap into active, illegal hacking.
## Risk C: Strict Privacy Jurisdictions (GDPR / CCPA)
If your stalker happens to be operating out of the European Union or certain strictly regulated states, an IP address is legally classified as Personally Identifiable Information (PII) under frameworks like GDPR. Collecting, processing, and storing that IP address without a clear privacy notice or explicit consent is technically a regulatory violation. While a criminal court in Michigan may not look favorably on a stalker complaining about their privacy, a civil privacy cross-complaint remains a theoretical leverage point for a sophisticated adversary.
## The Analytical Bottom Line
| Action Type | Legal Status | Structural Risk |
|---|---|---|
| Passive Web Beacon (CanaryToken PDF/Word) | Highly Defensible | Lowest risk; relies entirely on standard application behavior. |
| Active Code/Script Telemetry (Python Callback) | Defensible Gray Area | Safe only if limited strictly to basic public network handshakes. |
| Data Extraction / Payloads (Grabbing local files) | Strictly Illegal | Violates CFAA; constitutes an offensive cyber operation. |
If you restrict the mechanism purely to a passive beacon that alerts you when an asset you own is read, you are operating within established defensive cybersecurity norms. The moment the code executes an offensive function or touches data resident on their drive, the trap transforms into a liability.
