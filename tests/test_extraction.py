#!/usr/bin/env python3
"""
Test script to extract features from malware samples
Run this to see what features are extracted from your CAPEv2 JSON
"""

import sys
from pathlib import Path
from src.extractors.dynamic_features import DynamicFeatureExtractor


def print_section(title: str):
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def main():
    # take malware samples
    sample_dir = Path("data/malware_samples")
    json_files = list(sample_dir.glob("*.json"))

    if not json_files:
        print("No JSON files found in data/malware_samples/")
        sys.exit(1)

    # Process first sample
    sample_path = json_files[0]
    print(f"\n Analyzing: {sample_path.name}")

    # Extract features
    print("\n Extracting features...")
    extractor = DynamicFeatureExtractor(str(sample_path))
    features = extractor.extract_all()

    # Display results
    print_section("SAMPLE INFORMATION")
    print(f"Hash: {features['sample_hash']}")

    print_section("SUSPICIOUS REGISTRY KEYS")
    registry = features['suspicious_registry']
    if registry:
        print(f"Found {len(registry)} suspicious registry operations:\n")
        for i, reg in enumerate(registry[:10], 1):  # Show first 10
            print(f"{i}. {reg['key']}")
            print(f"   Category: {reg['category']}")
            print(f"   Pattern: {reg['pattern']}\n")
        if len(registry) > 10:
            print(f"... and {len(registry) - 10} more")
    else:
        print("No suspicious registry keys found")

    print_section("SUSPICIOUS API CALLS")
    api_calls = features['suspicious_api_calls']
    if api_calls.get('summary'):
        print(f"Found {len(api_calls['summary'])} different suspicious APIs:\n")
        print(f"{'API Name':<35} {'Count':<10} {'Category'}")
        print("-" * 70)
        for api in api_calls['summary'][:15]:  # Top 15
            print(f"{api['api']:<35} {api['count']:<10} {api['category']}")
    else:
        print("No suspicious API calls found")

    print_section("NETWORK ACTIVITY")
    network = features['network_activity']

    if network['domains']:
        print(f"\n Contacted Domains ({len(network['domains'])}):")
        for domain in network['domains'][:10]:
            print(f"  * {domain['domain']} → {domain['ip']}")
        if len(network['domains']) > 10:
            print(f"  ... and {len(network['domains']) - 10} more")

    if network['ips']:
        print(f"\n IP Addresses ({len(network['ips'])}):")
        for ip in network['ips'][:10]:
            print(f"  • {ip}")

    if network['urls']:
        print(f"\n HTTP Requests ({len(network['urls'])}):")
        for url in network['urls'][:5]:
            print(f"  * {url['method']} {url['url']}")

    if network['suspicious_ports']:
        print(f"\n  Suspicious Ports:")
        for port_info in network['suspicious_ports']:
            print(f"  * Port {port_info['port']} → {port_info['dst']}")

    if not any([network['domains'], network['ips'], network['urls']]):
        print("No network activity detected")

    print_section("FILE OPERATIONS")
    files = features['file_operations']
    if files:
        print(f"Found {len(files)} suspicious file operations:\n")
        for i, file_op in enumerate(files[:10], 1):
            print(f"{i}. {file_op['path']}")
            print(f"   Matched pattern: {file_op['pattern']}\n")
        if len(files) > 10:
            print(f"... and {len(files) - 10} more")
    else:
        print("No suspicious file operations found")

    print_section("PROCESS BEHAVIOR")
    processes = features['process_behavior']

    if processes['created_processes']:
        print(f"\n Created Processes ({len(processes['created_processes'])}):")
        for proc in processes['created_processes'][:5]:
            print(f"  * {proc['name']}")
            if proc['command_line']:
                print(f"    CMD: {proc['command_line'][:80]}")

    if processes['injected_processes']:
        print(f"\n Process Injection Detected ({len(processes['injected_processes'])}):")
        for inj in processes['injected_processes'][:5]:
            print(f"  * {inj['api']} by {inj['source']} → PID {inj['target_pid']}")

    print_section("BEHAVIOR SUMMARY")
    summary = features['behavior_summary']
    if summary:
        print("\nBehavior categories detected:\n")
        for category, count in sorted(summary.items(), key=lambda x: x[1], reverse=True):
            print(f"  {category:<30} : {count}")
    else:
        print("No behaviors categorized")

    print_section("HIGH-VALUE INDICATORS")
    discriminative = extractor.get_discriminative_features()
    if discriminative['high_value_indicators']:
        print("\n Most discriminative features for YARA rules:\n")
        for indicator in discriminative['high_value_indicators']:
            print(f"Type: {indicator['type']}")
            evidence_count = len(indicator['evidence'])
            print(f"Evidence count: {evidence_count}")
            print(f"Sample evidence: {indicator['evidence'][0]}")
            print()
    else:
        print("No high-value indicators identified")

    # Save to file
    output_file = Path("data/extracted_features.json")
    extractor.to_json(str(output_file))
    print(f"\n Full features saved to: {output_file}")


if __name__ == "__main__":
    main()
