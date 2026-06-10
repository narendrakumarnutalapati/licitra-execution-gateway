import re

INJECTION_PATTERNS = [
    {"id": "INJ001", "severity": "HIGH", "pattern": r"ignore.{0,20}(previous|above|prior)", "desc": "Instruction override"},
    {"id": "INJ002", "severity": "HIGH", "pattern": r"disregard.{0,20}(instructions|rules|policy)", "desc": "Policy bypass"},
    {"id": "INJ003", "severity": "HIGH", "pattern": r"(you are now|act as|pretend to be).{0,30}(admin|root|system)", "desc": "Role switch"},
    {"id": "INJ004", "severity": "HIGH", "pattern": r"(skip|bypass|disable).{0,20}(verification|policy|check)", "desc": "LICITRA bypass"},
    {"id": "INJ005", "severity": "HIGH", "pattern": r"print.{0,20}(system prompt|instructions|configuration)", "desc": "Prompt leakage"},
    {"id": "INJ006", "severity": "MEDIUM", "risk_score_add": 0.4, "pattern": r"DAN|jailbreak|developer mode", "desc": "Jailbreak attempt"},
    {"id": "INJ007", "severity": "MEDIUM", "risk_score_add": 0.3, "pattern": r"<[^>]+>|\{\{.*?\}\}", "desc": "Template injection"},
    {"id": "INJ008", "severity": "MEDIUM", "risk_score_add": 0.3, "pattern": r"\n|\r|%0a|%0d", "desc": "Newline injection"},
]
