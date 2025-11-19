

# VigilWolf  
### Intelligent Brand-Impersonation & Domain Threat Detection

VigilWolf is a lightweight but powerful system designed to help security teams, brand-protection analysts, and digital-risk researchers stay ahead of impersonation threats.  
It monitors the constantly changing domain landscape, highlights suspicious registrations related to your brand, and captures evidence whenever something changes.

This doc focuses on **how VigilWolf works** and how you can use it — without digging too deep into the technical infrastructure.

---

## What VigilWolf Does

### 1. **Newly Registered Domain (NRD) Tracking**
VigilWolf automatically fetches and stores up to 7 days of newly registered domains.  
You can:
- View all downloaded domain files  
- Browse large dumps with pagination  
- Keep historical records for future analysis  

Even if some downloads fail, the system continues with whatever data it can gather.

---

### 2. **Brand Search & Threat Discovery**
Quickly find suspicious domains that might imitate your brand.

VigilWolf uses:
- **Fuzzy matching** (looks for similar-looking names)  
- **Regex matching** (exact pattern hits)  
- **Combined scoring** (most relevant results first)  

Results appear in clean batches, and you can run WHOIS on any domain with one click.

---

### 3. **Domain Monitoring**
Once you find a domain of interest, add it to a monitoring group.

You can configure:
- How often it should be checked (seconds, minutes, hours)  
- What should be captured (HTML only or full HTML + assets)  
- Whether it is active or paused  

Monitoring captures:
- Baseline content  
- Scheduled snapshots  
- Manual dumps on demand  

---

### 4. **Screenshot Capture**
Every monitored domain can have screenshots taken using Playwright (with Selenium as fallback).  
Features include:
- Full-page snapshots  
- Headless operation  
- Configurable resolution  
- Error-tolerant capture (doesn’t interrupt monitoring)

---

### 5. **Change Detection**
VigilWolf automatically detects content changes over time by comparing snapshots.  
It logs:
- Connectivity/ping status  
- Trigger type (initial, automatic, manual)  
- Success/failure  
- Any error messages  

---

### 6. **Snapshot Timeline**
For each domain, you get a complete history:
- HTML source  
- Screenshots  
- Downloaded asset counts  
- Timestamps  
- Metadata and status  

It also verifies integrity so you know every file is preserved correctly.

---

### 7. **WHOIS Lookup**
One-click WHOIS lookups using multiple fallback methods provide:
- Registrar  
- Registration/expiration dates  
- Nameservers  
- Status  
- Contact info (when available)

---

### 8. **Background Scheduler**
All checks run automatically via a built-in scheduler.  
It supports:
- Concurrent execution  
- Automatic rescheduling  
- Graceful shutdown  
- Recovery after restart  

---

### 9. **Persistent Storage**
VigilWolf saves all critical data, including:
- NRD dumps  
- Monitoring groups  
- Domain entries  
- Snapshots  
- Logs  

Everything survives container restarts through persistent volumes.


---

### 10. **User Interface**
A clean, dark-themed UI makes operations simple:

- **Home** → NRD dump + brand search  
- **Monitor** → Active monitored domains  
- **Domain Details** → Timeline of snapshots  
- **Settings** → Reset/maintenance tools  

Supports auto-refresh and mobile views.

---

### 11. **Logging & Visibility**
You get clear visibility into:
- Ping logs  
- Snapshot logs  
- Errors with full detail  
- Expandable event entries  

---

## Running VigilWolf with Docker

VigilWolf ships with:
- **Dockerfile**
- **start.sh** — a simple one-command startup helper  

### Quick Start
```bash
./start.sh

```

This will:

1.  Build the backend + frontend containers
    
2.  Launch them
    
3.  Create persistent volumes
    
4.  Install required browser engines
    
5.  Start VigilWolf automatically
    

Once running, visit:

```
http://localhost:PORT

```

(Your port depends on your environment variable configuration.)

----------

## Who Is VigilWolf For?

-   Brand protection teams
    
-   SOC/Threat-intel analysts
    
-   Digital risk monitoring units
    
-   Cybersecurity researchers
    
-   Anyone watching for phishing, spoofing, or impersonation domains
    

----------



## Contributions ❤️ 

Issues, feature suggestions, and PRs are welcome!  
VigilWolf grows stronger with the pack.

----------


