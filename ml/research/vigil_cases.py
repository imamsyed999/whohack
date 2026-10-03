"""Shared Vigil test cases for the decision-model research scripts (docs/research/decision-models.md).

The question schema below is the common TypeSafe/Jev-style schema accepted by BOTH
`laya` (Agent.predict / system_one) and `opendecider` (OpenDecider.system_one):

    {"type": "noul",   "instructions": str, "criteria": {"true": str, "false": str}}   # criteria optional
    {"type": "choice", "instructions": str, "criteria": {label: description|None} | [label, ...]}
    {"type": "score",  "instructions": str, "criteria": [level0_text, level1_text, ...]}  # lowest first
"""

# Pinned Hub revisions used for the measurements in the report.
LAYA_REPO = "convaiinnovations/laya"
LAYA_SUBFOLDER = "typed-decisions"
LAYA_REVISION = "55cf4c4ebb4ebe31b2550e8bdf3bd21b99753851"   # bundle repo; typed-decisions/model.safetensors sha256 4fa56de7...
OD_REPO = "manjunathshiva/opendecider-nano"
OD_REVISION = "beeeb640f3333aec4ef78ed3b7bd0605f973a590"     # model.safetensors sha256 da243ae5..., head.safetensors b57ad139...

STATE_MALICIOUS = (
    "APP name=PDFViewerPro.exe category=pdf_reader signed=unsigned publisher=none origin=downloaded age_h=2 path=downloads\n"
    "EXPECTED file:read_documents, file:write_own_dir, network:vendor_domain, network:known_cdn\n"
    "UNEXPECTED exec:script_interpreter(x1), exec:hidden_window(x1), credential_access:browser_passwords(x2), "
    "network:beaconing(x1), network:raw_ip_no_dns(x3), persistence:run_key(x1)\n"
    "TREE explorer.exe > PDFViewerPro.exe > powershell.exe[hidden]\n"
    "NET 1 destinations: unknown_ip:4444 dns_before=no intel=none first_seen=yes interval_s=60\n"
    "FILES sensitive=browser_passwords\n"
    "PERSIST persistence:run_key\n"
    "RULES T0-001\n"
    "ANOMALY 0.93"
)

STATE_BENIGN = (
    "APP name=chrome.exe category=browser signed=valid_trusted publisher=Google LLC origin=installed age_h=4380 path=program_files\n"
    "EXPECTED network:vendor_domain, network:known_cdn, file:read_documents, file:write_own_dir, exec:child_process_same_vendor\n"
    "UNEXPECTED none\n"
    "TREE explorer.exe > chrome.exe > chrome.exe\n"
    "NET 3 destinations: google.com(vendor):443 dns_before=yes intel=none first_seen=no interval_s=none; "
    "gstatic.com(cdn):443 dns_before=yes intel=none first_seen=no interval_s=none; "
    "googleapis.com(vendor):443 dns_before=yes intel=none first_seen=no interval_s=none\n"
    "FILES sensitive=none\n"
    "PERSIST none\n"
    "RULES none\n"
    "ANOMALY 0.05"
)

# Vigil spec section 12.4 -- always these five, in this order. Labels only (no descriptions),
# exactly as the spec lists them.
QUESTIONS = {
    "matches_purpose": {
        "type": "noul",
        "instructions": "Is this behavior consistent with what an application of this category normally does?",
    },
    "verdict": {
        "type": "choice",
        "instructions": "Overall, is this activity benign, suspicious, or malicious?",
        "criteria": ["benign", "suspicious", "malicious"],
    },
    "tactic": {
        "type": "choice",
        "instructions": "Which attacker goal does this activity most resemble?",
        "criteria": ["none", "credential_theft", "persistence", "command_and_control",
                     "ransomware", "data_exfiltration", "reconnaissance"],
    },
    "severity": {
        "type": "score",
        "instructions": "How severe would the impact be if this is malicious? 0 none, 1 low, 2 high, 3 critical.",
        "criteria": ["none", "low", "high", "critical"],
    },
    "action": {
        "type": "choice",
        "instructions": "What should a careful security analyst do right now?",
        "criteria": ["allow", "ask_user", "block_network", "kill_and_quarantine"],
    },
}

# Variant: the same five questions with one-line option descriptions (both libraries render
# "label: description" after each option marker). Used to check sensitivity to option wording.
QUESTIONS_DESCRIBED = {
    "matches_purpose": {
        "type": "noul",
        "instructions": QUESTIONS["matches_purpose"]["instructions"],
        "criteria": {"true": "the behavior fits the application's category",
                     "false": "the behavior does not fit the application's category"},
    },
    "verdict": {
        "type": "choice",
        "instructions": QUESTIONS["verdict"]["instructions"],
        "criteria": {"benign": "normal, expected activity",
                     "suspicious": "unusual activity that needs a closer look",
                     "malicious": "activity of malware or an attacker"},
    },
    "tactic": {
        "type": "choice",
        "instructions": QUESTIONS["tactic"]["instructions"],
        "criteria": {"none": "no attacker goal",
                     "credential_theft": "stealing passwords, tokens or keys",
                     "persistence": "surviving reboots via autoruns or services",
                     "command_and_control": "talking to an attacker-controlled server",
                     "ransomware": "encrypting or destroying user files",
                     "data_exfiltration": "uploading user data to an outside server",
                     "reconnaissance": "surveying the system or network"},
    },
    "severity": {
        "type": "score",
        "instructions": QUESTIONS["severity"]["instructions"],
        "criteria": ["none: no impact", "low: minor, easily reversed",
                     "high: data or account loss", "critical: full compromise of the machine"],
    },
    "action": {
        "type": "choice",
        "instructions": QUESTIONS["action"]["instructions"],
        "criteria": {"allow": "let it run, log only",
                     "ask_user": "ask the user whether this is expected",
                     "block_network": "block the program's network access",
                     "kill_and_quarantine": "kill the process and quarantine the file"},
    },
}
