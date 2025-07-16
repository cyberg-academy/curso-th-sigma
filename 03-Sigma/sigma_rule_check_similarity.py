
import os
import yaml
from difflib import SequenceMatcher
import json

RULES_PATH = "../rules/"
SIMILARITY_THRESHOLD = 0.8

new_rule = """
title: MacOS Scripting Interpreter AppleScript
id: 1bc2e6c5-0885-472b-bed6-be5ea8eace55
status: test
description: Detects execution of AppleScript of the macOS scripting language AppleScript.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1059.002/T1059.002.md
    - https://redcanary.com/blog/applescript/
author: Alejandro Ortuno, oscd.community
date: 2020-10-21
modified: 2023-02-01
tags:
    - attack.execution
    - attack.t1059.002
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        Image|contains: 
            - '/osascript'
            - '/script'
        CommandLine|contains:
            - ' -e '
            - '.scpt'
            - '.js'
            - '.json'
    condition: selection
falsepositives:
    - Application installers might contain scripts as part of the installation process.
level: medium
"""

def calculate_similarity(str1, str2):
    """
    Calculate similarity between two strings using SequenceMatcher.
    Returns a float between 0 and 1, where 1 is identical.
    """
    if not str1 or not str2:
        return 0.0
    return SequenceMatcher(None, str1.lower(), str2.lower()).ratio()

def normalize_detection_section(detection):
    """
    Convert detection section to a normalized string for comparison.
    """
    if not detection or not isinstance(detection, dict):
        return ""
    
    # Convert detection dict to JSON string for comparison
    # Sort keys to ensure consistent ordering
    try:
        return json.dumps(detection, sort_keys=True, default=str)
    except:
        return str(detection)

def load_rule_from_string(rule_string):
    """
    Parse a YAML rule string and return the parsed data.
    """
    try:
        return yaml.safe_load(rule_string)
    except yaml.YAMLError as e:
        print(f"Error parsing new rule YAML: {e}")
        return None

def load_existing_rules():
    """
    Load all existing Sigma rules from the rules directory.
    Returns a list of tuples: (filepath, rule_data)
    """
    rules = []
    
    if not os.path.exists(RULES_PATH):
        print(f"Rules directory '{RULES_PATH}' not found.")
        return rules
    
    for dirpath, _, filenames in os.walk(RULES_PATH):
        for filename in filenames:
            if filename.lower().endswith(('.yml', '.yaml')):
                filepath = os.path.join(dirpath, filename)
                try:
                    with open(filepath, "r", encoding="utf-8") as file:
                        rule_data = yaml.safe_load(file)
                        if rule_data:
                            rules.append((filepath, rule_data))
                except yaml.YAMLError as e:
                    print(f"Error parsing YAML in {filepath}: {e}")
                    continue
                except Exception as e:
                    print(f"Error reading file {filepath}: {e}")
                    continue
    
    return rules

def check_rule_similarity(new_rule_data, existing_rules):
    """
    Check similarity between the new rule and existing rules.
    Returns a list of similar rules with similarity scores.
    """
    if not new_rule_data:
        return []
    
    new_title = new_rule_data.get('title', '').strip()
    new_detection = normalize_detection_section(new_rule_data.get('detection', {}))
    
    similar_rules = []
    
    for filepath, existing_rule in existing_rules:
        existing_title = existing_rule.get('title', '').strip()
        existing_detection = normalize_detection_section(existing_rule.get('detection', {}))
        
        # Calculate similarity for title and detection sections
        title_similarity = calculate_similarity(new_title, existing_title)
        detection_similarity = calculate_similarity(new_detection, existing_detection)
        
        # Combined similarity score (weighted average)
        # Give more weight to detection section as it's more critical
        combined_similarity = (title_similarity * 0.3) + (detection_similarity * 0.7)
        
        if combined_similarity >= SIMILARITY_THRESHOLD:
            similar_rules.append({
                'filepath': filepath,
                'title': existing_title,
                'title_similarity': title_similarity,
                'detection_similarity': detection_similarity,
                'combined_similarity': combined_similarity
            })
    
    # Sort by combined similarity (highest first)
    similar_rules.sort(key=lambda x: x['combined_similarity'], reverse=True)
    return similar_rules

def main():
    """
    Main function to check rule similarity.
    """
    print("Loading new rule...")
    new_rule_data = load_rule_from_string(new_rule)
    
    if not new_rule_data:
        print("Error: Could not parse the new rule.")
        return
    
    print("Loading existing rules...")
    existing_rules = load_existing_rules()
    print(f"Loaded {len(existing_rules)} existing rules.")
    
    print(f"\nChecking similarity with threshold: {SIMILARITY_THRESHOLD * 100}%")
    print(f"New rule title: '{new_rule_data.get('title', 'N/A')}'")
    print("-" * 60)
    
    similar_rules = check_rule_similarity(new_rule_data, existing_rules)
    
    if similar_rules:
        print(f"Found {len(similar_rules)} similar rule(s):")
        print()
        
        for i, similar_rule in enumerate(similar_rules, 1):
            print(f"{i}. Similar rule found:")
            print(f"   File: {similar_rule['filepath']}")
            print(f"   Title: {similar_rule['title']}")
            print(f"   Title similarity: {similar_rule['title_similarity']:.2%}")
            print(f"   Detection similarity: {similar_rule['detection_similarity']:.2%}")
            print(f"   Combined similarity: {similar_rule['combined_similarity']:.2%}")
            print()
    else:
        print("OK - No similar rules found. You can create this rule.")

if __name__ == "__main__":
    main()
