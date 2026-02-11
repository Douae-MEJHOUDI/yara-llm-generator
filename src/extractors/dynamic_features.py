"""
Dynamic Feature Extractor
Extracts behavioral features from CAPEv2 JSON reports
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Any
from collections import defaultdict

from ..config.suspicious_indicators import (
    SUSPICIOUS_API_CALLS,
    SUSPICIOUS_REGISTRY_PATTERNS,
    SUSPICIOUS_FILE_PATHS,
    SUSPICIOUS_PORTS,
    BEHAVIOR_CATEGORIES
)


class DynamicFeatureExtractor:
    """Extracts discriminative features from CAPEv2 behavioral analysis"""

    def __init__(self, json_path: str):
        """
        Initialize extractor with CAPEv2 JSON report

        Args:
            json_path: Path to CAPEv2 JSON file
        """
        self.json_path = Path(json_path)
        self.data = self._load_json()
        self.features = {}

    def _load_json(self) -> Dict:
        """Load and parse JSON file"""
        try:
            with open(self.json_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            raise ValueError(f"Failed to load JSON: {e}")

    def extract_all(self) -> Dict[str, Any]:
        """
        Extract all features from the report

        Returns:
            Dictionary containing all extracted features
        """
        self.features = {
            "sample_hash": self._get_sample_hash(),
            "suspicious_registry": self._extract_registry_features(),
            "suspicious_api_calls": self._extract_api_features(),
            "network_activity": self._extract_network_features(),
            "file_operations": self._extract_file_features(),
            "process_behavior": self._extract_process_features(),
            "behavior_summary": self._categorize_behaviors(),
        }
        return self.features

    def _get_sample_hash(self) -> str:
        """Extract sample hash from filename or data"""
        # Try to get from filename first
        filename = self.json_path.stem
        if len(filename) == 64:  # SHA256
            return filename

        # Try to get from JSON data
        if "target" in self.data and "file" in self.data["target"]:
            return self.data["target"]["file"].get("sha256", "unknown")

        return filename

    def _extract_registry_features(self) -> List[Dict]:
        """Extract suspicious registry operations"""
        suspicious_keys = []

        # Get all registry keys from behavior summary
        if "behavior" not in self.data or "summary" not in self.data["behavior"]:
            return suspicious_keys

        all_keys = self.data["behavior"]["summary"].get("keys", [])

        # Filter for suspicious patterns
        for key in all_keys:
            for pattern in SUSPICIOUS_REGISTRY_PATTERNS:
                if pattern.lower() in key.lower():
                    suspicious_keys.append({
                        "key": key,
                        "pattern": pattern,
                        "category": self._classify_registry_key(key)
                    })
                    break  # Avoid duplicates

        return suspicious_keys

    def _classify_registry_key(self, key: str) -> str:
        """Classify registry key by behavior type"""
        key_lower = key.lower()

        if "run" in key_lower or "startup" in key_lower:
            return "persistence"
        elif "policy" in key_lower or "policies" in key_lower:
            return "policy_modification"
        elif "service" in key_lower:
            return "service_manipulation"
        elif "image file execution" in key_lower:
            return "debugger_hijacking"
        else:
            return "registry_modification"

    def _extract_api_features(self) -> Dict:
        """Extract suspicious API calls"""
        suspicious_apis = []
        api_counts = defaultdict(int)

        # Get API calls from process behavior
        if "behavior" not in self.data or "processes" not in self.data["behavior"]:
            return {"detailed": [], "summary": []}

        for process in self.data["behavior"]["processes"]:
            process_name = process.get("process_name", "unknown")

            for call in process.get("calls", []):
                api_name = call.get("api", "")

                # Check if API is suspicious
                if api_name in SUSPICIOUS_API_CALLS:
                    api_counts[api_name] += 1

                    # Only include first few occurrences to avoid clutter
                    if api_counts[api_name] <= 3:
                        suspicious_apis.append({
                            "api": api_name,
                            "process": process_name,
                            "category": self._classify_api_call(api_name),
                            "arguments": call.get("arguments", {})
                        })

        # Add summary counts
        api_summary = [
            {"api": api, "count": count, "category": self._classify_api_call(api)}
            for api, count in sorted(api_counts.items(), key=lambda x: x[1], reverse=True)
        ]

        return {
            "detailed": suspicious_apis[:20],  # Limit to top 20
            "summary": api_summary
        }

    def _classify_api_call(self, api_name: str) -> str:
        """Classify API call by behavior category"""
        api_lower = api_name.lower()

        for category, keywords in BEHAVIOR_CATEGORIES.items():
            for keyword in keywords:
                if keyword.lower() in api_lower:
                    return category

        return "other"

    def _extract_network_features(self) -> Dict:
        """Extract network activity"""
        network_features = {
            "domains": [],
            "ips": [],
            "urls": [],
            "suspicious_ports": []
        }

        if "network" not in self.data:
            return network_features

        network_data = self.data["network"]

        # Extract domains
        if "domains" in network_data:
            network_features["domains"] = [
                {"domain": d["domain"], "ip": d.get("ip", "unknown")}
                for d in network_data["domains"]
            ]

        # Extract IPs
        if "hosts" in network_data:
            network_features["ips"] = network_data["hosts"]

        # Extract HTTP requests
        if "http" in network_data:
            network_features["urls"] = [
                {
                    "method": req.get("method", "GET"),
                    "url": req.get("uri", ""),
                    "host": req.get("host", "")
                }
                for req in network_data["http"][:10]  # Limit to first 10
            ]

        # Check for suspicious ports
        if "tcp" in network_data:
            for conn in network_data["tcp"]:
                port = conn.get("dport", 0)
                if port in SUSPICIOUS_PORTS:
                    network_features["suspicious_ports"].append({
                        "port": port,
                        "dst": conn.get("dst", "")
                    })

        return network_features

    def _extract_file_features(self) -> List[Dict]:
        """Extract suspicious file operations"""
        suspicious_files = []

        if "behavior" not in self.data or "summary" not in self.data["behavior"]:
            return suspicious_files

        all_files = self.data["behavior"]["summary"].get("files", [])

        # Filter for suspicious paths
        for file_path in all_files:
            for pattern in SUSPICIOUS_FILE_PATHS:
                if pattern.lower() in file_path.lower():
                    suspicious_files.append({
                        "path": file_path,
                        "pattern": pattern
                    })
                    break

        return suspicious_files[:20]  # Limit to top 20

    def _extract_process_features(self) -> Dict:
        """Extract process creation and manipulation"""
        process_info = {
            "created_processes": [],
            "injected_processes": []
        }

        if "behavior" not in self.data or "processes" not in self.data["behavior"]:
            return process_info

        for process in self.data["behavior"]["processes"]:
            process_name = process.get("process_name", "")

            # Look for process creation
            if process.get("first_seen"):
                process_info["created_processes"].append({
                    "name": process_name,
                    "command_line": process.get("command_line", "")
                })

            # Look for injection indicators
            for call in process.get("calls", [])[:100]:  # Check first 100 calls
                api = call.get("api", "")
                if api in ["CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx"]:
                    target_pid = call.get("arguments", {}).get("process_identifier")
                    if target_pid:
                        process_info["injected_processes"].append({
                            "api": api,
                            "source": process_name,
                            "target_pid": target_pid
                        })

        return process_info

    def _categorize_behaviors(self) -> Dict[str, int]:
        """
        Summarize behaviors by category for quick overview

        Returns:
            Count of behaviors per category
        """
        categories = defaultdict(int)

        # Count registry-based behaviors
        for reg in self.features.get("suspicious_registry", []):
            categories[reg["category"]] += 1

        # Count API-based behaviors
        if "summary" in self.features.get("suspicious_api_calls", {}):
            for api in self.features["suspicious_api_calls"]["summary"]:
                categories[api["category"]] += 1

        # Network activity
        net = self.features.get("network_activity", {})
        if net.get("domains"):
            categories["network_communication"] += len(net["domains"])

        return dict(categories)

    def get_discriminative_features(self, min_score: float = 2.0) -> Dict:
        """
        Filter for most discriminative features (high signal, low noise)

        Args:
            min_score: Minimum importance score

        Returns:
            Filtered features likely to be unique to malware
        """
        if not self.features:
            self.extract_all()

        discriminative = {
            "high_value_indicators": [],
            "score_breakdown": {}
        }

        # High-value: Process injection
        if self.features["process_behavior"]["injected_processes"]:
            discriminative["high_value_indicators"].append({
                "type": "process_injection",
                "evidence": self.features["process_behavior"]["injected_processes"]
            })

        # High-value: Persistence mechanisms
        persistence_keys = [
            reg for reg in self.features["suspicious_registry"]
            if reg["category"] == "persistence"
        ]
        if persistence_keys:
            discriminative["high_value_indicators"].append({
                "type": "persistence",
                "evidence": persistence_keys
            })

        # High-value: Anti-analysis
        anti_analysis_apis = [
            api for api in self.features["suspicious_api_calls"].get("summary", [])
            if api["category"] == "anti_analysis"
        ]
        if anti_analysis_apis:
            discriminative["high_value_indicators"].append({
                "type": "anti_analysis",
                "evidence": anti_analysis_apis
            })

        return discriminative

    def to_dict(self) -> Dict:
        """Export features as dictionary"""
        if not self.features:
            self.extract_all()
        return self.features

    def to_json(self, output_path: str = None) -> str:
        """
        Export features as JSON

        Args:
            output_path: Optional path to save JSON file

        Returns:
            JSON string
        """
        if not self.features:
            self.extract_all()

        json_str = json.dumps(self.features, indent=2)

        if output_path:
            with open(output_path, 'w') as f:
                f.write(json_str)

        return json_str
