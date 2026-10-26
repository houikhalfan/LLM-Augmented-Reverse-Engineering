# 🔬 LLM-Augmented Reverse Engineering

> Assistant d'aide au reverse engineering de code malveillant décompilé :
> explication sémantique et extraction automatique d'IoCs

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Ollama](https://img.shields.io/badge/Ollama-qwen2.5--coder:7b-black?logo=ollama)](https://ollama.com)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.30+-FF4B4B?logo=streamlit&logoColor=white)](https://streamlit.io)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white)](https://docker.com)
[![License](https://img.shields.io/badge/License-Academic-yellow)]()

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Problem Statement](#-problem-statement)
- [Architecture](#-architecture)
- [Features](#-features)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Running with Docker](#running-with-docker)
  - [Running Locally](#running-locally)
- [Usage](#-usage)
  - [API](#api)
  - [Web Interface](#web-interface)
- [Dataset](#-dataset)
- [MITRE ATT&CK Mapping](#-mitre-attck-mapping)
- [Evaluation](#-evaluation)
- [Team & Roles](#-team--roles)
- [Roadmap](#-roadmap)
- [Security Considerations](#-security-considerations)
- [References](#-references)

---

## 🧠 Overview

**LLM-Augmented Reverse Engineering** is a tool designed to assist SOC analysts and CERT teams in analyzing decompiled malware. It combines **deterministic extraction** with **LLM-powered semantic analysis** to:

1. **Extract IoCs** (IP addresses, domains, registry keys) with guaranteed 100% recall
2. **Explain code logic** by generating documented pseudo-code and summaries
3. **Block hallucinations** by cross-verifying every LLM output against the raw source code
4. **Map behaviors** to the MITRE ATT&CK framework automatically
5. **Export results** in JSON and STIX formats for SIEM/MISP integration

---

## 🎯 Problem Statement

Reverse engineering a malware sample takes **hours of manual work** and requires rare expertise. SOC/CERT teams receive more samples than they can analyze — IoCs reach defense teams too late, extending the exposure window.

**How can we use a code-specialized LLM to accelerate understanding of decompiled code and automatically extract reliable IoCs, without producing hallucinated information?**

---

## 🏗 Architecture

The pipeline combines deterministic methods with LLM analysis so that reliability never depends on the model alone:

```
                         ┌─────────────────────────┐
                         │   Decompiled C Code      │
                         │   (Ghidra pseudo-C)      │
                         └────────────┬─────────────┘
                                      │
                         ┌────────────▼─────────────┐
                         │  1. PREPROCESSING         │
                         │  • Function splitting      │
                         │  • Artifact cleanup        │
                         │  • Stack string rebuild    │
                         │  • XOR / Base64 decode     │
                         └─────┬──────────────┬──────┘
                               │              │
                    Raw code   │              │  Cleaned code
                    + decoded  │              │
                    strings    │              │
                               │              │
              ┌────────────────▼──┐    ┌──────▼──────────────┐
              │ 2. DETERMINISTIC   │    │ 3. LLM ANALYSIS     │
              │    EXTRACTOR       │    │    (Ollama)          │
              │ • Regex: IPs,      │    │ • Semantic explain   │
              │   domains,         │    │ • Pseudo-code gen    │
              │   registry keys    │    │ • JSON-constrained   │
              └────────┬──────────┘    └──────┬──────────────┘
                       │                      │
                       │         ┌────────────▼─────────────┐
                       │         │ 4. ANTI-HALLUCINATION     │
                       │         │ • Cross-check vs raw code │
                       │         │ • Found → ✅ confirmed     │
                       │         │ • Not found → ❌ rejected  │
                       │         └────────────┬─────────────┘
                       │                      │
                       └──────────┬───────────┘
                                  │
                     ┌────────────▼─────────────┐
                     │ 5. STRUCTURED OUTPUT      │
                     │ • Human-readable report    │
                     │ • JSON / STIX export       │
                     │ • MITRE ATT&CK mapping     │
                     └──────────────────────────┘
```

---

## ✨ Features

- **🎯 100% IoC Recall** — Deterministic regex extraction on raw + decoded strings guarantees no IoC is missed (within defined scope)
- **🤖 Semantic Code Explanation** — LLM generates readable summaries and documented pseudo-code for complex functions
- **🛡️ Zero Hallucinated IoCs** — Every entity the LLM produces is cross-verified against the source; unverifiable claims are flagged
- **🗺️ MITRE ATT&CK Auto-Mapping** — Detected behaviors are automatically mapped to ATT&CK technique IDs
- **📦 STIX/JSON Export** — IoCs are exported in standard formats for direct SIEM/MISP ingestion
- **🖥️ SOC Dashboard** — Streamlit-based web interface for pasting code, viewing results, and exporting
- **🐳 One-Command Deploy** — Full Docker containerization

---

## 🛠 Tech Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Language | Python 3.10+ | Core pipeline |
| LLM | Ollama + `qwen2.5-coder:7b` | Semantic analysis, constrained JSON output |
| API | FastAPI | `/analyze` endpoint |
| UI | Streamlit | SOC analyst dashboard |
| Containers | Docker | One-command deployment |
| Decompiler | Ghidra (headless) | Binary → pseudo-C conversion |
| Export | JSON / STIX | Standard IoC formats |

---

## 📁 Project Structure

```
.
├── preprocessing/          # Code cleaning and decoding
│   ├── splitter.py         # Function-level segmentation of pseudo-C
│   ├── cleaner.py          # Decompiler artifact removal (undefined4, unaff_*, dead code)
│   ├── stack_strings.py    # Stack string reconstruction algorithm
│   └── decoders.py         # XOR (constant key) and Base64 decoders
│
├── extractor/              # Deterministic IoC extraction
│   ├── regex_extractor.py  # IPv4/IPv6, domain, registry key patterns
│   └── scorer.py           # Recall / precision scoring against ground truth
│
├── llm/                    # LLM integration layer
│   ├── ollama_client.py    # Ollama API wrapper
│   ├── prompts.py          # Prompt templates for analysis
│   └── schema.py           # JSON output schema constraints
│
├── verification/           # Anti-hallucination layer
│   └── verifier.py         # Cross-check LLM output vs raw code + decoded strings
│
├── mitre/                  # MITRE ATT&CK mapping
│   └── mapper.py           # Behavior → technique ID mapping
│
├── api/                    # FastAPI backend
│   └── main.py             # /analyze endpoint
│
├── ui/                     # Streamlit frontend
│   └── app.py              # SOC analyst dashboard
│
├── data/
│   ├── synthetic/          # Synthetic C samples (source, compiled, decompiled)
│   └── ground_truth/       # JSON annotations per sample
│
├── tests/                  # Unit and integration tests
│
├── Dockerfile              # Container configuration
├── docker-compose.yml      # Multi-service orchestration
├── requirements.txt        # Python dependencies
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites

- **Python** 3.10+
- **Docker** (recommended) or local Python environment
- **Ollama** installed with `qwen2.5-coder:7b` model pulled
- **Ghidra** (for decompiling your own binaries — optional)

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd llm-reverse-engineering

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Pull the LLM model
ollama pull qwen2.5-coder:7b
```

### Running with Docker

```bash
# Build and start all services
docker-compose up --build

# Or run standalone
docker build -t llm-reveng .
docker run -p 8000:8000 -p 8501:8501 llm-reveng
```

### Running Locally

```bash
# Start the Ollama server (in a separate terminal)
ollama serve

# Start the FastAPI backend
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload

# Start the Streamlit UI (in a separate terminal)
streamlit run ui/app.py --server.port 8501
```

---

## 📖 Usage

### API

Send decompiled C code to the `/analyze` endpoint:

```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "code": "void FUN_00401000(void) { char *ip = \"192.168.1.100\"; ... }"
  }'
```

**Response:**

```json
{
  "iocs": {
    "ip_addresses": ["192.168.1.100"],
    "domains": ["malware-c2.evil.com"],
    "registry_keys": ["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"]
  },
  "mitre_mapping": [
    {"behavior": "Hardcoded IP", "technique": "C2 Communication", "id": "T1071"}
  ],
  "llm_analysis": {
    "summary": "This function establishes a reverse TCP connection to ...",
    "pseudo_code": "...",
    "hallucination_flags": []
  },
  "stix_bundle": { "..." }
}
```

### Web Interface

1. Open `http://localhost:8501` in your browser
2. Paste decompiled C code into the input area
3. Click **Analyze**
4. View extracted IoCs, MITRE mappings, and LLM explanation
5. Export results as JSON or STIX

---

## 📊 Dataset

### Synthetic Dataset (Primary)

We generate our own dataset for controlled evaluation:

| Step | Tool | Output |
|------|------|--------|
| Write C files with planted IoCs | Manual | 8–10 `.c` files |
| Compile | `gcc` | ELF binaries |
| Strip symbols | `strip --strip-unneeded` | Stripped binaries |
| Decompile | Ghidra headless | Pseudo-C files |
| Annotate | Manual + regex | Ground truth JSON |

**Obfuscation levels:**

| Level | Technique | Example |
|-------|-----------|---------|
| 🟢 Cleartext | Plain string | `"192.168.1.100"` |
| 🟡 XOR | Constant-key XOR | `xor_decode(buf, 0x42)` |
| 🟠 Base64 | Base64 encoding | `"MTkyLjE2OC4xLjEwMA=="` |
| 🔴 Stack string | Char-by-char on stack | `s[0]='1'; s[1]='9'; s[2]='2'; ...` |

### Fallback Dataset

[Malware VX-Underground 2024 – Code and Decompiled](https://huggingface.co/datasets/qwewerewq/malware-vxunderground-2024-code-decompiled) (Hugging Face) — real malware source code + decompiled pseudo-C.

---

## 🗺 MITRE ATT&CK Mapping

| Detected Behavior | Technique | ATT&CK ID |
|---|---|---|
| Hardcoded IP address | Command & Control Communication | T1071 |
| Run/RunOnce registry key | Boot or Logon Autostart Execution | T1547.001 |
| XOR-encoded strings | Obfuscated Files or Information | T1027 |
| Runtime Base64 decoding | Deobfuscate/Decode Files or Information | T1140 |
| Stack strings | Software Packing / Obfuscation | T1027.002 |

---

## 📈 Evaluation

| Metric | Target | Method |
|--------|--------|--------|
| **IoC Recall** | 100% | Deterministic extractor vs ground truth (on in-scope obfuscation levels) |
| **IoC Precision** | > 95% | False positive analysis |
| **Code Summary Quality** | ≥ 4/5 | Manual evaluation on 5-point rubric by reverse engineer |
| **Time Reduction** | > 80% | Comparison with manual analysis time |
| **Live Demo Speed** | < 30s | End-to-end: obfuscated input → full report |
| **Hallucinated IoCs** | 0 | Anti-hallucination layer verification |

---

## 👥 Team & Roles

| Role | Responsibilities |
|------|-----------------|
| **Lead Data / ML Engineer** | LLM setup (Ollama + qwen2.5-coder:7b), prompt engineering, JSON schema constraints, scoring scripts, token reduction analysis |
| **Lead SecOps & Threat Analyst** | Synthetic C file creation, Ghidra decompilation, ground truth annotation, stack string reconstruction, XOR/Base64 decoding, MITRE ATT&CK mapping |
| **Lead Integration & Dev** | FastAPI `/analyze` endpoint, Docker containerization, Streamlit UI, STIX/JSON export |
| **Red Teamer & Evaluator** | Evasion testing (heavy obfuscation, junk code, function renaming), false positive analysis, anti-hallucination verification, explainability (IoC → line number) |

---

## 🗓 Roadmap

| Sprint | Phase | Focus |
|--------|-------|-------|
| **Sprint 1** ✅ | Business Understanding & Data Collection | Problem definition, dataset selection, project plan |
| **Sprint 2** 🔄 | Data Preparation & Initial Modeling | Synthetic dataset, preprocessing pipeline, deterministic extractor, anti-hallucination layer, first LLM test, FastAPI + Streamlit + Docker |
| **Sprint 3** ⬜ | Full Modeling & Evaluation | Full LLM integration, formal evaluation (recall/precision/rubric), red teaming, explainability, live demo preparation |
| **Sprint 4** ⬜ | Final Demo & Report | Live demonstration (< 30s), final report, documentation |

---

## 🔒 Security Considerations

- **Isolated VM** — All analysis runs in a network-isolated virtual machine with snapshots
- **No execution** — Malware samples are **never executed**; only decompiled text is processed
- **Local LLM** — The model runs locally via Ollama; no code is sent to external APIs
- **Static analysis only** — The entire pipeline operates on text, not live binaries

---

## 📚 References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Ollama Documentation](https://ollama.com/)
- [Ghidra](https://ghidra-sre.org/)
- [STIX 2.1 Specification](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
- [VX-Underground Dataset (HuggingFace)](https://huggingface.co/datasets/qwewerewq/malware-vxunderground-2024-code-decompiled)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Streamlit Documentation](https://docs.streamlit.io/)

---

<p align="center">
  <em>Built as part of the LLM-Augmented Reverse Engineering academic project (Sujet 2.2)</em>
</p>
