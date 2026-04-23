"""
src/nlp/classifier.py
NLP-based threat classifier using TF-IDF + Logistic Regression.
Also maps threats to MITRE ATT&CK tactics and techniques.
This is the ELITE AI component.
"""
import json
import pickle
import os
from typing import Dict, List, Tuple, Optional
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder

from src.utils.logger import get_logger

logger = get_logger("cti.nlp.classifier")

MODEL_PATH = Path("data/models/classifier.pkl")

# ─── Training Data ────────────────────────────────────────────────────────────
# In production: load from a labelled dataset. Here we use seed data.

TRAINING_DATA = [
    # Malware
    ("trojan backdoor remote access tool RAT keylogger spyware", "Malware"),
    ("malware payload dropper loader stager shellcode", "Malware"),
    ("botnet C2 command control beacon callback", "Malware"),
    ("worm propagation self-replicating network spread", "Malware"),
    ("rootkit stealth persistence kernel driver", "Malware"),

    # Ransomware
    ("ransomware encryption files locked ransom bitcoin payment", "Ransomware"),
    ("encrypt documents ransom demand decrypt key", "Ransomware"),
    ("double extortion data leak ransomware group", "Ransomware"),
    ("lockbit conti blackcat alphv ransomware attack", "Ransomware"),

    # Phishing
    ("phishing email credential harvesting fake login page", "Phishing"),
    ("spear phishing targeted email social engineering", "Phishing"),
    ("smishing vishing SMS voice phishing credentials", "Phishing"),
    ("impersonation brand spoofing account takeover phishing", "Phishing"),

    # DDoS
    ("DDoS distributed denial of service flood amplification", "DDoS"),
    ("UDP flood SYN flood HTTP flood volumetric attack", "DDoS"),
    ("amplification reflection NTP DNS memcached DDoS", "DDoS"),
    ("botnet coordinated attack service disruption bandwidth", "DDoS"),

    # Exploit / RCE
    ("buffer overflow remote code execution arbitrary code", "Remote Code Execution"),
    ("heap spray use-after-free memory corruption exploit", "Remote Code Execution"),
    ("RCE unauthenticated pre-auth code execution vulnerability", "Remote Code Execution"),
    ("deserialization exploit gadget chain remote execution", "Remote Code Execution"),

    # SQL Injection
    ("SQL injection database query union select bypass", "SQL Injection"),
    ("blind SQLi error-based time-based database extraction", "SQL Injection"),
    ("ORM injection parameterized query bypass database", "SQL Injection"),

    # XSS
    ("cross-site scripting XSS reflected stored DOM-based", "Cross-Site Scripting"),
    ("JavaScript injection cookie theft session hijacking XSS", "Cross-Site Scripting"),
    ("CSP bypass XSS polyglot script injection", "Cross-Site Scripting"),

    # Privilege Escalation
    ("privilege escalation local exploit sudo misconfig kernel", "Privilege Escalation"),
    ("elevation of privilege EoP SYSTEM admin root access", "Privilege Escalation"),
    ("token impersonation pass-the-hash NTLM relay escalation", "Privilege Escalation"),

    # Supply Chain
    ("supply chain attack dependency confusion npm package malicious", "Supply Chain"),
    ("SolarWinds build pipeline CI/CD compromise upstream", "Supply Chain"),
    ("typosquatting package repository poisoning supply chain", "Supply Chain"),

    # Zero Day
    ("zero-day 0day unpatched unknown vulnerability in the wild", "Zero Day"),
    ("no patch available active exploitation zero day", "Zero Day"),
    ("undisclosed vulnerability weaponized exploit zero-day", "Zero Day"),
]

# ─── MITRE ATT&CK Mapping ─────────────────────────────────────────────────────

MITRE_MAPPING = {
    "Malware": {
        "tactic": "Execution",
        "technique": "T1204",
        "technique_name": "User Execution",
        "keywords": ["payload", "dropper", "loader", "trojan", "backdoor"],
    },
    "Ransomware": {
        "tactic": "Impact",
        "technique": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "keywords": ["encrypt", "ransom", "lockbit", "conti"],
    },
    "Phishing": {
        "tactic": "Initial Access",
        "technique": "T1566",
        "technique_name": "Phishing",
        "keywords": ["email", "credential", "spear", "smishing"],
    },
    "DDoS": {
        "tactic": "Impact",
        "technique": "T1498",
        "technique_name": "Network Denial of Service",
        "keywords": ["flood", "amplification", "volumetric"],
    },
    "Remote Code Execution": {
        "tactic": "Execution",
        "technique": "T1203",
        "technique_name": "Exploitation for Client Execution",
        "keywords": ["buffer overflow", "rce", "arbitrary code"],
    },
    "SQL Injection": {
        "tactic": "Collection",
        "technique": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "keywords": ["sql", "injection", "union", "select"],
    },
    "Cross-Site Scripting": {
        "tactic": "Collection",
        "technique": "T1185",
        "technique_name": "Browser Session Hijacking",
        "keywords": ["xss", "javascript", "cookie"],
    },
    "Privilege Escalation": {
        "tactic": "Privilege Escalation",
        "technique": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
        "keywords": ["escalation", "sudo", "kernel", "privilege"],
    },
    "Supply Chain": {
        "tactic": "Initial Access",
        "technique": "T1195",
        "technique_name": "Supply Chain Compromise",
        "keywords": ["supply chain", "dependency", "npm", "package"],
    },
    "Zero Day": {
        "tactic": "Execution",
        "technique": "T1203",
        "technique_name": "Exploitation for Client Execution",
        "keywords": ["zero-day", "0day", "unpatched"],
    },
    "Unknown": {
        "tactic": "Unknown",
        "technique": "",
        "technique_name": "Unknown",
        "keywords": [],
    },
}


class ThreatClassifier:
    def __init__(self):
        self.pipeline: Optional[Pipeline] = None
        self.classes: List[str] = []
        self._load_or_train()

    def _build_pipeline(self) -> Pipeline:
        return Pipeline([
            ("tfidf", TfidfVectorizer(
                ngram_range=(1, 3),
                max_features=10000,
                sublinear_tf=True,
                min_df=1,
                strip_accents="unicode",
            )),
            ("clf", LogisticRegression(
                max_iter=1000,
                C=1.0,
                class_weight="balanced",
                solver="lbfgs",
            )),
        ])

    def _load_or_train(self):
        if MODEL_PATH.exists():
            try:
                with open(MODEL_PATH, "rb") as f:
                    data = pickle.load(f)
                    self.pipeline = data["pipeline"]
                    self.classes = data["classes"]
                logger.info("Loaded pre-trained classifier model")
                return
            except Exception as e:
                logger.warning(f"Could not load model, retraining: {e}")

        self._train()

    def _train(self):
        """Train classifier on seed data."""
        texts = [t[0] for t in TRAINING_DATA]
        labels = [t[1] for t in TRAINING_DATA]
        self.classes = list(set(labels))

        self.pipeline = self._build_pipeline()
        self.pipeline.fit(texts, labels)

        # Save model
        MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(MODEL_PATH, "wb") as f:
            pickle.dump({"pipeline": self.pipeline, "classes": self.classes}, f)

        logger.info(f"Classifier trained on {len(texts)} examples, {len(self.classes)} classes")

    def classify(self, text: str) -> Dict:
        """
        Classify a threat description.
        Returns: category, confidence, all_scores, mitre mapping.
        """
        if not text or not self.pipeline:
            return self._unknown_result()

        try:
            proba = self.pipeline.predict_proba([text])[0]
            classes = self.pipeline.classes_
            top_idx = np.argmax(proba)
            category = classes[top_idx]
            confidence = float(proba[top_idx])

            all_scores = {cls: round(float(p), 4) for cls, p in zip(classes, proba)}
            mitre = self._get_mitre_mapping(category, text)

            return {
                "category": category,
                "confidence": round(confidence, 4),
                "all_scores": all_scores,
                "mitre_tactic": mitre["tactic"],
                "mitre_technique": mitre["technique"],
                "mitre_technique_name": mitre["technique_name"],
            }
        except Exception as e:
            logger.error(f"Classification error: {e}")
            return self._unknown_result()

    def _get_mitre_mapping(self, category: str, text: str) -> Dict:
        """Get MITRE ATT&CK info for a category, refined by text."""
        base = MITRE_MAPPING.get(category, MITRE_MAPPING["Unknown"])

        # Keyword-based refinement for more specific techniques
        text_lower = text.lower()

        if category == "Malware":
            if any(k in text_lower for k in ["rootkit", "kernel", "stealth"]):
                return {"tactic": "Defense Evasion", "technique": "T1014",
                        "technique_name": "Rootkit"}
            if any(k in text_lower for k in ["keylog", "credential"]):
                return {"tactic": "Credential Access", "technique": "T1056.001",
                        "technique_name": "Keylogging"}

        if category == "Remote Code Execution":
            if "deserialization" in text_lower:
                return {"tactic": "Execution", "technique": "T1059",
                        "technique_name": "Command and Scripting Interpreter"}

        return base

    def _unknown_result(self) -> Dict:
        return {
            "category": "Unknown",
            "confidence": 0.0,
            "all_scores": {},
            "mitre_tactic": "Unknown",
            "mitre_technique": "",
            "mitre_technique_name": "Unknown",
        }

    def retrain(self, additional_data: List[Tuple[str, str]]):
        """Add new labelled examples and retrain."""
        global TRAINING_DATA
        TRAINING_DATA.extend(additional_data)
        logger.info(f"Retraining with {len(additional_data)} additional examples")
        self._train()


# Singleton
_classifier = None

def get_classifier() -> ThreatClassifier:
    global _classifier
    if _classifier is None:
        _classifier = ThreatClassifier()
    return _classifier
