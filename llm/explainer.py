"""
explainer.py  —  LLM-based semantic explanation of decompiled C code
Sujet 2.2 : LLM-Augmented Reverse Engineering

- Sends decompiled C code to Ollama (qwen2.5:3b)
- Forces structured JSON output
- Verifies every IoC the LLM mentions against the raw code (anti-hallucination)
- Maps detected behaviors to MITRE ATT&CK techniques
"""

import json
import re
import sys
import urllib.request
import urllib.error
from pathlib import Path

# ── import extractor for anti-hallucination verification ─────────────────────
sys.path.insert(0, str(Path(__file__).parent.parent / "extractor"))
from extractor import extract

# ─────────────────────────────────────────────────────────────────────────────
# MITRE ATT&CK MAPPING
# ─────────────────────────────────────────────────────────────────────────────

MITRE_RULES = [
    (r'HKCU.*CurrentVersion.*Run|HKLM.*CurrentVersion.*Run',
     "T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys"),
    (r'Winlogon.*Shell|Winlogon.*Userinit',
     "T1547.004", "Boot or Logon Autostart Execution: Winlogon Helper DLL"),
    (r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
     "T1071",     "Application Layer Protocol: C2 Communication"),
    (r'[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}',
     "T1071",     "Application Layer Protocol: C2 Communication"),
    (r'0x[0-9a-fA-F]{2}\s*\^|XOR|xor',
     "T1027",     "Obfuscated Files or Information: XOR encoding"),
    (r'base64|b64',
     "T1140",     "Deobfuscate/Decode Files or Information"),
    (r'\[\d+\]\s*=\s*0x[0-9a-fA-F]{2}',
     "T1027.002", "Obfuscated Files or Information: Stack Strings"),
    (r'RegSetValue|RegOpenKey|RegCreateKey',
     "T1112",     "Modify Registry"),
    (r'socket|connect|send|recv|WSAStartup',
     "T1095",     "Non-Application Layer Protocol"),
]

def map_mitre(code: str) -> list[dict]:
    seen = set()
    results = []
    for pattern, tid, name in MITRE_RULES:
        if re.search(pattern, code, re.IGNORECASE) and tid not in seen:
            seen.add(tid)
            results.append({"technique_id": tid, "technique_name": name})
    return results


# ─────────────────────────────────────────────────────────────────────────────
# ANTI-HALLUCINATION LAYER
# ─────────────────────────────────────────────────────────────────────────────

def verify_iocs(llm_iocs: dict, raw_code: str, extracted_iocs: dict) -> dict:
    """
    Cross-check every IoC the LLM mentions against:
      1. The raw source code (literal search)
      2. The deterministic extractor output
    Returns verified and hallucinated lists.
    """
    verified      = {"ips": [], "domains": [], "registry_keys": []}
    hallucinated  = {"ips": [], "domains": [], "registry_keys": []}

    for ioc_type in ["ips", "domains", "registry_keys"]:
        for ioc in llm_iocs.get(ioc_type, []):
            in_code      = ioc in raw_code
            in_extractor = ioc in extracted_iocs.get(ioc_type, [])
            if in_code or in_extractor:
                verified[ioc_type].append(ioc)
            else:
                hallucinated[ioc_type].append(ioc)

    return {"verified": verified, "hallucinated": hallucinated}


# ─────────────────────────────────────────────────────────────────────────────
# OLLAMA CALL
# ─────────────────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a malware reverse engineering assistant.
Analyze the decompiled C code provided and respond ONLY with a valid JSON object.
No explanation, no markdown, no code blocks. Only raw JSON.

The JSON must have exactly this structure:
{
  "summary": "One sentence: what this code does from an attacker's perspective.",
  "attack_logic": "2-3 sentences describing the attack behavior step by step.",
  "suspicious_functions": ["list", "of", "suspicious", "function", "names"],
  "iocs_mentioned": {
    "ips": ["only IPs you can literally see in the code"],
    "domains": ["only domains you can literally see in the code"],
    "registry_keys": ["only registry keys you can literally see in the code"]
  },
  "risk_level": "LOW | MEDIUM | HIGH | CRITICAL"
}

CRITICAL RULE: Only include IoCs that are LITERALLY present in the code.
Never invent or guess any IP, domain, or registry key."""


def call_ollama(code: str, model: str = "qwen2.5:3b") -> dict:
    payload = {
        "model": model,
        "stream": False,
        "format": "json",
        "system": SYSTEM_PROMPT,
        "prompt": f"Analyze this decompiled C code:\n\n{code}"
    }

    data = json.dumps(payload).encode("utf-8")
    req  = urllib.request.Request(
        "http://localhost:11434/api/generate",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            raw = json.loads(resp.read().decode("utf-8"))
            return json.loads(raw["response"])
    except urllib.error.URLError:
        return {"error": "Ollama not running. Start it with: ollama serve"}
    except (json.JSONDecodeError, KeyError) as e:
        return {"error": f"Failed to parse LLM response: {e}"}


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ANALYSIS FUNCTION
# ─────────────────────────────────────────────────────────────────────────────

def analyze(filepath: str, model: str = "qwen2.5:3b") -> dict:
    raw_code = Path(filepath).read_text(encoding="utf-8", errors="ignore")

    print(f"  [1/4] Running deterministic extractor...")
    extracted_iocs = extract(filepath)

    print(f"  [2/4] Calling LLM ({model})...")
    llm_output = call_ollama(raw_code, model)

    if "error" in llm_output:
        return {"file": filepath, "error": llm_output["error"]}

    print(f"  [3/4] Verifying LLM IoCs (anti-hallucination)...")
    llm_iocs   = llm_output.get("iocs_mentioned", {})
    ioc_check  = verify_iocs(llm_iocs, raw_code, extracted_iocs)

    print(f"  [4/4] Mapping MITRE ATT&CK techniques...")
    mitre      = map_mitre(raw_code)

    return {
        "file":               Path(filepath).name,
        "risk_level":         llm_output.get("risk_level", "UNKNOWN"),
        "summary":            llm_output.get("summary", ""),
        "attack_logic":       llm_output.get("attack_logic", ""),
        "suspicious_functions": llm_output.get("suspicious_functions", []),
        "iocs": {
            "extracted_deterministic": extracted_iocs,
            "llm_verified":            ioc_check["verified"],
            "llm_hallucinated":        ioc_check["hallucinated"],
        },
        "mitre_attack":       mitre,
    }


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python explainer.py <file.c>")
        sys.exit(1)

    filepath = sys.argv[1]
    model    = sys.argv[2] if len(sys.argv) > 2 else "qwen2.5:3b"

    print(f"\nAnalyzing: {filepath}\n")
    result = analyze(filepath, model)

    print("\n" + "="*60)
    print(json.dumps(result, indent=2))
    print("="*60)
