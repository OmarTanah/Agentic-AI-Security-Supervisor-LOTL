# 🛡️ LOTL-ARIA: Agentic LLM Framework for LOTL Attack Investigation

> **Status:** 🚧 **Work in Progress (Semester 1)** 🚧
> *This project is currently under active development as part of our Bachelor's graduation thesis.*

**LOTL-ARIA** (Agentic Response and Investigation for Attacks) is an autonomous cybersecurity framework that bridges the gap between passive Machine Learning detectors and active, investigating LLM agents. It specifically targets **Linux Living-off-the-Land (LOTL)** attacks.

Instead of relying on rigid rules or black-box ML models, LOTL-ARIA uses a **ReAct (Reasoning + Acting)** LLM agent to investigate raw system events (from `auditd` and `sudo` logs), form dual hypotheses (malicious vs. benign), and propose a graded response. To ensure safety, all agent actions must pass through a **Multi-Layer Deterministic Safety Gate** to prevent prompt injection attacks.

## 📖 Documentation
- [Research Paper](docs/Agentic-LOTL-Attack-Supervisor.pdf)

## 🏗️ Architecture
*(The following diagrams illustrate the target architecture for the completed project)*

### System Architecture
![System Architecture](System-Architecture.jpg)

### Process Flowchart
![Process Flowchart](diagrams/Flowchart-Diagram.jpg)

## 🚀 Current Progress (Semester 1)
- [x] Literature Review (11 recent papers)
- [x] Identification of 3 Core Research Gaps (Context, Response, Safety)
- [x] System Architecture & Flowchart Design
- [x] **Layer 1: Data Ingestion & Normalization** (Completed)
  - Wazuh integration (raw log forwarding)
  - Multi-layer De-obfuscation (Base64, Hex, ANSI-C)
  - Heuristic Severity Scoring
  - SQLite Audit Database & Deduplication

## ⚙️ How to Run (Layer 1 Prototype)

### Prerequisites
- Python 3.10+
- Wazuh Manager installed and configured to forward events.

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/OmarTanah/LOTL-ARIA.git
   cd LOTL-ARIA
   ```
2. Create a virtual environment and install dependencies:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```
3. Start the Flask webhook (Layer 1):
   ```bash
   python -m src.layer1.webhook
   ```
   *The server will start on `http://0.0.0.0:5000`.*

## 👥 Team
- **Omar Tanah**
- **Louay Almarri**
- **Hamza Beirouti**

**Supervisors:** Dr. Waseem Juneidi, Eng. Ahmad Shekha
**Institution:** Syrian Private University - Faculty of Artificial Intelligence Engineering
```
