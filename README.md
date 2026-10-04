# SPOOR

### Evidence-Backed Cyber Attack Reconstruction

> **Follow the intruder's trail.**

Spoor is an evidence-driven cybersecurity investigation platform that transforms thousands of fragmented security events into a single, understandable attack story.

Instead of forcing analysts to investigate isolated alerts across different log sources, Spoor detects suspicious activity, correlates related events across users, IPs, hosts and sessions, reconstructs the attack campaign, and connects the resulting conclusions back to the underlying evidence.

---

## The Problem

Modern security environments generate thousands of authentication, web-server and network events.

The challenge is not simply detecting suspicious events.

The harder problem is answering:

> **Which events belong to the same attack, how did the attacker move through the system, and what evidence proves it?**

Traditional alert-driven investigation can leave analysts with fragmented signals and a large amount of noise.

Spoor focuses on reconstructing the **story behind the alerts**.

---

# The Solution

Spoor processes security events through an investigation pipeline:

```text
Raw Security Logs
       ↓
Parsing & Normalization
       ↓
Suspicious Activity Detection
       ↓
Behavioral Analysis
       ↓
Cross-Event Correlation
       ↓
Attack Campaign Reconstruction
       ↓
Kill-Chain Mapping
       ↓
Evidence-Backed Investigation
```

The result is a human-readable attack investigation instead of a collection of disconnected alerts.

---

# Key Features

### 🔍 Multi-Source Log Analysis

Processes authentication, web-server and network events and normalizes them into a common event representation.

### 🧠 Behavioral Detection

Combines security rules and behavioral signals to identify suspicious activity and deviations from expected behavior.

### 🔗 Cross-Event Correlation

Connects users, IP addresses, hosts, sessions and related events into candidate attack campaigns.

### 🕵️ Attack Reconstruction

Reconstructs the sequence of an intrusion into a kill-chain style timeline.

### 🌐 IP-Rotation Correlation

Related attacker activity can still be connected even when the source IP changes during the attack.

### 📜 Evidence-Backed Findings

Important investigation findings can be traced back to the underlying log events that support them.

### ▶️ Attack Replay

Allows investigators to step through the reconstructed attack and understand how the campaign unfolded.

### 🕸️ Attack-Path Visualization

Visualizes relationships between attackers, users, hosts and other entities involved in the investigation.

### 🛡️ Benign Activity Analysis

Evaluates alternative benign explanations to reduce false-positive incidents.

### 🧪 Synthetic Evaluation

Includes randomized attack scenarios with hidden ground truth for testing detection, correlation and reconstruction behavior.

---

# What Makes Spoor Different?

Most security tools can tell an analyst:

> **"This event looks suspicious."**

Spoor tries to answer the more useful question:

> **"What happened, how are these events connected, and what evidence supports that conclusion?"**

The core idea is:

```text
Thousands of Events
        ↓
     Signals
        ↓
   Correlation
        ↓
 Attack Campaign
        ↓
 Evidence + Story
```

---

# Example Investigation

A typical investigation may contain a sequence such as:

```text
Reconnaissance
      ↓
Credential Access
      ↓
Initial Access
      ↓
Privilege Escalation
      ↓
Persistence
      ↓
Data Access / Exfiltration
```

Spoor correlates the underlying events and presents them as one investigation rather than unrelated alerts.

---

# Architecture

```text
┌───────────────────────────┐
│      Security Logs        │
│ Auth / Web / Network      │
└─────────────┬─────────────┘
              ↓
┌───────────────────────────┐
│ Parsing & Normalization   │
└─────────────┬─────────────┘
              ↓
┌───────────────────────────┐
│ Detection Layer           │
│ Rules + Behavioral Signals│
└─────────────┬─────────────┘
              ↓
┌───────────────────────────┐
│ Correlation Engine        │
│ User / IP / Host / Time   │
└─────────────┬─────────────┘
              ↓
┌───────────────────────────┐
│ Campaign Reconstruction   │
│ Kill-Chain Mapping        │
└─────────────┬─────────────┘
              ↓
┌───────────────────────────┐
│ Investigation Interface   │
│ Timeline / Graph / Evidence│
└───────────────────────────┘
```

---

# Technology Stack

The project uses the technologies and libraries present in this repository.

### Core

* Python
* HTML
* CSS
* JavaScript

### Security / Analysis

* Log parsing and normalization
* Rule-based detection
* Behavioral analysis
* Event correlation
* Attack campaign reconstruction
* Kill-chain mapping
* Evidence extraction

### Evaluation

* Synthetic attack generation
* Ground-truth scenarios
* Precision / recall evaluation
* False-positive analysis
* Campaign reconstruction testing

> See `requirements.txt` and the source code for the exact dependencies used by the implementation.

---

# Evaluation

Spoor includes a synthetic evaluation framework designed to test the implemented attack scenarios and correlation pipeline against randomized data with hidden ground truth.

Our current evaluation achieved:

* **100% Precision**
* **100% Recall**
* **60 randomized scenarios successfully evaluated**

These results are intended to validate the behavior of the implemented synthetic attack family and correlation pipeline. They should **not** be interpreted as a claim of universal real-world cybersecurity accuracy.

---

# Demo

### Live Demo

**[Add deployed URL here]**

### Demonstration Video

**[Add Google Drive / video URL here]**

Recommended demo flow:

```text
Generate Scenario
       ↓
Analyze Logs
       ↓
Open Incident
       ↓
Attack Replay
       ↓
Attack Path
       ↓
Evidence
       ↓
Benign Analysis
```

---

# Screenshots

## Investigation Dashboard

![Spoor Dashboard](docs/screenshots/dashboard.png)

## Attack Reconstruction

![Attack Reconstruction](docs/screenshots/incident.png)

## Attack Path

![Attack Path](docs/screenshots/attack-path.png)

## Evidence

![Evidence](docs/screenshots/evidence.png)

---

# Running Locally

## 1. Clone the repository

```bash
git clone (https://github.com/Bhavesh13s/Spoor-Evidence-Backed-Cyber-Attack-Reconstruction.git)
cd spoor
```

## 2. Create a virtual environment

### Windows

```bash
python -m venv .venv
.venv\Scripts\activate
```

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
```

## 3. Install dependencies

```bash
pip install -r requirements.txt
```

## 4. Start the application

Use the startup command corresponding to the project's backend.

Example:

```bash
python app.py
```

or:

```bash
python main.py
```

> Replace this command with the actual command used by the current project.

## 5. Open the local application

```text
http://localhost:8000
```

Use the port shown by the application if it differs.

---

# Project Status

### Hackathon Submission — Algothon'26

Problem Statement:

**ALG-CYBER-01 — Find the Intruder**

Spoor is presented as a functional prototype demonstrating the complete investigation workflow from security-event ingestion through detection, correlation, attack reconstruction and evidence presentation.

---

# Limitations & Future Work

Spoor is currently a prototype focused on demonstrating the attack reconstruction and investigation workflow.

Potential future improvements include:

* Integration with production SIEM systems
* Additional log formats
* Larger real-world datasets
* More attack families
* Threat-intelligence enrichment
* Streaming / real-time ingestion
* Analyst collaboration
* Additional MITRE ATT&CK techniques
* Production-scale deployment

---

# Hackathon

Built for **Algothon'26**.

### Spoor

> **Follow the intruder's trail.**
