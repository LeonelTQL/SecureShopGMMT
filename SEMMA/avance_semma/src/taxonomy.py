"""Identifiers from PDF §4; only evidenced categories are trained."""
from .common import ROOT, save_json

TOP = {
    "A01:2025": "Broken Access Control",
    "A02:2025": "Security Misconfiguration",
    "A03:2025": "Software Supply Chain Failures",
    "A04:2025": "Cryptographic Failures",
    "A05:2025": "Injection",
    "A06:2025": "Insecure Design",
    "A07:2025": "Authentication Failures",
    "A08:2025": "Software or Data Integrity Failures",
    "A09:2025": "Security Logging and Alerting Failures",
    "A10:2025": "Mishandling of Exceptional Conditions",
}
API = {
    "API1:2023": "Broken Object Level Authorization",
    "API2:2023": "Broken Authentication",
    "API3:2023": "Broken Object Property Level Authorization",
    "API4:2023": "Unrestricted Resource Consumption",
    "API5:2023": "Broken Function Level Authorization",
    "API6:2023": "Unrestricted Access to Sensitive Business Flows",
    "API7:2023": "Server Side Request Forgery",
    "API8:2023": "Security Misconfiguration",
    "API9:2023": "Improper Inventory Management",
    "API10:2023": "Unsafe Consumption of APIs",
}
# Benchmark ground truth CWE -> official Top 10 2025 lists; no automatic API equivalence.
CWE_TOP = {22: "A01:2025", 78: "A05:2025", 79: "A05:2025", 89: "A05:2025",
           90: "A05:2025", 327: "A04:2025", 328: "A04:2025", 330: "A04:2025",
           614: "A02:2025", 643: "A05:2025"}


def export_catalog(evaluated):
    save_json(ROOT / "data/processed/catalogo_owasp.json", [
        {"id": key, "name": name, "estado": "evaluada_en_dataset" if key in evaluated else "no_evaluada",
         "nota": "Cobertura experimental; no implica detección funcional de repositorios."}
        for key, name in {**TOP, **API}.items()
    ])
