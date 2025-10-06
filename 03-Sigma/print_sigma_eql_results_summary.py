#!/usr/bin/env python3
"""
Test script to demonstrate the summary functionality on existing results
"""
import json
from sigma_to_eql_converter import print_summary

# Load the most recent results file
with open('2025-09-14_12-09-56_sigma_eql_results.json', 'r', encoding='utf-8') as f:
    results = json.load(f)

# Print the summary
print_summary(results)