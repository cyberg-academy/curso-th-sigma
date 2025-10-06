#!/usr/bin/env python3
"""
Sigma to EQL Converter
This script reads Sigma rules, converts them to EQL queries, and executes them against Elasticsearch.
"""
import json
import os
import glob
from datetime import datetime
from dotenv import load_dotenv
from elasticsearch import Elasticsearch
from sigma.rule import SigmaRule
from sigma.backends.elasticsearch import EqlBackend
from sigma.pipelines.elasticsearch import (
    ecs_windows,
    zeek as ecs_zeek,
    ecs_kubernetes
)

load_dotenv()

"""
Global configuration: folder or specific file is allowed. 
    # Examples:
        - "../rules/sigma-community/windows/process_creation/proc_creation_win_acccheckconsole_execution.yml"
        - "../rules/sigma-community/windows/process_creation/"
        - "../rules/sigma-community/"
"""
SIGMA_RULES_PATH = "../rules/sigma-community/windows/process_creation/proc_creation_win_acccheckconsole_execution.yml"
ELASTICSEARCH_HOST = "https://localhost:9200"
ELASTICSEARCH_INDEX = "cyberg-th-lab"  # Default index pattern
MAX_RESULTS_DISPLAY = 15


def read_sigma_rules(rules_path):
    """
    Read all Sigma rules from the specified path.
    
    Args:
        rules_path (str): Path to directory containing .yml rule files or single .yml file
        
    Returns:
        list: List of tuples containing (filename, SigmaRule object)
    """
    rules = []
    
    if os.path.isfile(rules_path) and rules_path.endswith('.yml'):
        # Single file
        yml_files = [rules_path]
    else:
        # Directory - search recursively
        yml_files = glob.glob(os.path.join(rules_path, "**", "*.yml"), recursive=True)
    
    for yml_file in yml_files:
        try:
            with open(yml_file, 'r', encoding='utf-8') as f:
                rule_content = f.read()
                # Skip template files or files without proper Sigma structure
                if 'title:' not in rule_content and 'logsource:' not in rule_content:
                    continue
                    
                sigma_rule = SigmaRule.from_yaml(rule_content)
                rules.append((os.path.basename(yml_file), sigma_rule))
                print(f" Loaded rule: {os.path.basename(yml_file)}")
        except Exception as e:
            print(f" Error loading {yml_file}: {str(e)}")
            continue
    
    return rules


def convert_sigma_to_eql(sigma_rule):
    """
    Convert a Sigma rule to EQL query using pySigma.
    
    Args:
        sigma_rule (SigmaRule): Sigma rule object
        
    Returns:
        str: EQL query string or None if conversion fails
    """
    try:
        # Convert the rule to EQL query
        # Create a Sigma rule object
        # sigma_rule_obj = SigmaCollection.from_yaml(sigma_rule)

        if sigma_rule.logsource.product == "windows":
            pipeline = ecs_windows()
        elif sigma_rule[0].logsource.product == "zeek":
            pipeline = ecs_zeek()
        elif sigma_rule[0].logsource.product == "kubernetes":
            pipeline = ecs_kubernetes()
        else:
            pipeline = ecs_windows()

        # Initialize the Elasticsearch backend
        backend = EqlBackend(pipeline)

        # Convert the collection
        query = backend.convert_rule(sigma_rule)[0]

        if isinstance(query, str):
            return query
        else:
            return None
            
    except Exception as e:
        print(f" Error converting rule to EQL: {str(e)}")
        return None


def connect_to_elasticsearch():
    """
    Connect to Elasticsearch instance.
    
    Returns:
        Elasticsearch: Elasticsearch client or None if connection fails
    """
    try:
        api_key = os.getenv('ELASTIC_API_KEY')
        if not api_key:
            print(" ELASTIC_API_KEY not found in environment variables")
            return None
            
        es = Elasticsearch(
            [ELASTICSEARCH_HOST],
            api_key=api_key,
            verify_certs=False,
            request_timeout=30
        )
        
        # Test connection
        if es.ping():
            print(f" Connected to Elasticsearch at {ELASTICSEARCH_HOST}")
            return es
        else:
            print(f" Cannot connect to Elasticsearch at {ELASTICSEARCH_HOST}")
            return None
            
    except Exception as e:
        print(f" Elasticsearch connection error: {str(e)}")
        return None


def execute_eql_query(es_client, eql_query):
    """
    Execute EQL query against Elasticsearch.
    
    Args:
        es_client (Elasticsearch): Elasticsearch client
        eql_query (str): EQL query to execute
        
    Returns:
        tuple: (results, total_hits) or (None, 0) if query fails
    """
    try:
        body_query = {
            "query": eql_query,
            "tiebreaker_field": "@timestamp",
            "size": 1000,
        }
        
        response = es_client.eql.search(
            index=ELASTICSEARCH_INDEX,
            body=body_query,
        )

        events = response.body.get('hits', {}).get('events', [])
        total_hits = response.body.get('hits', {}).get('total', {}).get('value', 0)

        return events, total_hits
        
    except Exception as e:
        print(f" Error executing query: {str(e)}")
        return None, 0


def print_results(results, total_hits, rule_name):
    """
    Print query results with formatting.
    
    Args:
        results (list): List of search results
        total_hits (int): Total number of hits
        rule_name (str): Name of the Sigma rule
    """
    print(f"\n{'='*60}")
    print(f"Results for rule: {rule_name}")
    print(f"{'='*60}")
    
    if total_hits == 0:
        print("No events found.")
        return
    
    # Display up to MAX_RESULTS_DISPLAY events
    display_count = min(len(results), MAX_RESULTS_DISPLAY)
    
    for i, hit in enumerate(results[:display_count]):
        source = hit.get('_source', {})

        print(f"\nEvent {i+1}:")
        print(json.dumps(source, indent=4))

    if total_hits > MAX_RESULTS_DISPLAY:
        print(f"\n... and {total_hits - MAX_RESULTS_DISPLAY} more events (total: {total_hits})")
    else:
        print(f"\nTotal events: {total_hits}")


def main():
    """
    Main function to orchestrate the Sigma to EQL conversion and execution.
    """
    print("Sigma to EQL Converter")
    print("="*40)
    
    # Check if rules path exists
    if not os.path.exists(SIGMA_RULES_PATH):
        print(f" Rules path does not exist: {SIGMA_RULES_PATH}")
        return
    
    # Read Sigma rules
    print(f"\nReading Sigma rules from: {SIGMA_RULES_PATH}")
    rules = read_sigma_rules(SIGMA_RULES_PATH)
    
    if not rules:
        print("No valid Sigma rules found.")
        return
    
    print(f"Found {len(rules)} valid Sigma rules.")
    
    # Connect to Elasticsearch
    print("\nConnecting to Elasticsearch...")
    es_client = connect_to_elasticsearch()
    
    if not es_client:
        print("Cannot proceed without Elasticsearch connection.")
        return
    
    # Process each rule
    print(f"\nProcessing rules against index: {ELASTICSEARCH_INDEX}")

    # Prepare var for saving results in file
    output = {}

    for rule_filename, sigma_rule in rules:
        print(f"\n{'*'*50}")
        print(f"Processing: {rule_filename}")
        print(f"{'*'*50}")
        
        # Convert to EQL
        eql_query = convert_sigma_to_eql(sigma_rule)
        
        if not eql_query:
            print(f" Could not convert rule to EQL")
            continue
        
        print(f"EQL Query:\n{eql_query}")


        # Fill output dict
        if rule_filename not in output:
            # sigma_rule output:
            try:
                rule_dict = sigma_rule.to_dict()
            except Exception as e:
                rule_dict = {"error": f"Could not convert rule to dict: {str(e)}"}

            output[rule_filename] = {
                "sigma_rule": rule_dict,
                "eql_query": eql_query,
                "total_events": 0,
                "events": []
            }

        # Execute query
        events, total_events = execute_eql_query(es_client, eql_query)
        
        if events is not None:
            print_results(events, total_events, rule_filename)
            # Save results to output dict
            output[rule_filename]["total_events"] = total_events
            output[rule_filename]["events"] = events
        else:
            print(f" Query execution failed")

    # Save all results to a JSON file with timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_filename = f"{timestamp}_sigma_eql_results.json"
    with open(output_filename, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=4)

    print(f"{'#'*50}")
    print(f"\nResults saved to {output_filename}")
    print(f"{'#'*50}")

    # Generate and print summary
    print_summary(output)


def print_summary(results):
    """
    Print a comprehensive summary of the Sigma rules execution results.

    Args:
        results (dict): Dictionary containing all rule execution results
    """
    total_rules = len(results)
    successful_rules = 0
    error_rules = 0
    total_events_matched = 0
    rules_with_events = 0

    # Count by level
    level_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    level_events = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}

    # Lists for detailed reporting
    successful_rules_details = []
    error_rules_details = []

    for rule_filename, rule_data in results.items():
        sigma_rule = rule_data.get("sigma_rule", {})
        total_events = rule_data.get("total_events", 0)
        eql_query = rule_data.get("eql_query", "")

        # Check if rule has error in sigma_rule
        if "error" in sigma_rule:
            error_rules += 1
            error_rules_details.append({
                "filename": rule_filename,
                "title": "Error in rule conversion",
                "level": "unknown",
                "events": 0
            })
            continue

        # Check if EQL query was generated successfully
        if not eql_query:
            error_rules += 1
            error_rules_details.append({
                "filename": rule_filename,
                "title": sigma_rule.get("title", "Unknown"),
                "level": sigma_rule.get("level", "unknown"),
                "events": 0
            })
            continue

        # Rule executed successfully
        successful_rules += 1
        level = sigma_rule.get("level", "informational").lower()
        title = sigma_rule.get("title", "Unknown")

        # Normalize level names
        if level not in level_counts:
            level = "informational"

        level_counts[level] += 1
        level_events[level] += total_events
        total_events_matched += total_events

        if total_events > 0:
            rules_with_events += 1

        successful_rules_details.append({
            "filename": rule_filename,
            "title": title,
            "level": level,
            "events": total_events
        })

    # Print summary header
    print(f"\n{'='*80}")
    print(f"SIGMA RULES EXECUTION SUMMARY")
    print(f"{'='*80}")

    # Main summary line
    print(f"\nFrom {total_rules} sigma rules executed, {successful_rules} has been executed successfully, {error_rules} with errors,")
    print(f"From the {successful_rules} rules executed successfully, {rules_with_events} have generated {total_events_matched} events matched.")
    print(f"\nIn the following we show the name of the rules and title, the number of events matched by level, from critical to informational:")

    # Show summary of rules with events
    if rules_with_events > 0:
        print(f"\nRULES WITH MATCHED EVENTS:")
        print(f"{'Rule File':<50} {'Title':<60} {'Level':<12} {'Events':<8}")
        print(f"{'-'*132}")
        rules_with_events_sorted = [r for r in successful_rules_details if r["events"] > 0]
        rules_with_events_sorted.sort(key=lambda x: x["events"], reverse=True)
        for rule in rules_with_events_sorted:
            filename = rule["filename"][:47] + "..." if len(rule["filename"]) > 50 else rule["filename"]
            title = rule["title"][:57] + "..." if len(rule["title"]) > 60 else rule["title"]
            level = rule["level"].capitalize()
            print(f"{filename:<50} {title:<60} {level:<12} {rule['events']:<8}")
        print()

    # Summary by level
    print(f"\n{'Level':<15} {'Rules':<8} {'Events':<10}")
    print(f"{'-'*35}")
    for level in ["critical", "high", "medium", "low", "informational"]:
        print(f"{level.capitalize():<15} {level_counts[level]:<8} {level_events[level]:<10}")

    print(f"{'-'*35}")
    print(f"{'Total':<15} {successful_rules:<8} {total_events_matched:<10}")

    # Detailed results by level (only rules with events > 0)
    for level in ["critical", "high", "medium", "low", "informational"]:
        rules_at_level = [r for r in successful_rules_details if r["level"] == level and r["events"] > 0]
        if rules_at_level:
            print(f"\n{level.upper()} LEVEL RULES WITH EVENTS:")
            print(f"{'Rule File':<50} {'Title':<60} {'Events':<8}")
            print(f"{'-'*120}")
            for rule in sorted(rules_at_level, key=lambda x: x["events"], reverse=True):
                filename = rule["filename"][:47] + "..." if len(rule["filename"]) > 50 else rule["filename"]
                title = rule["title"][:57] + "..." if len(rule["title"]) > 60 else rule["title"]
                print(f"{filename:<50} {title:<60} {rule['events']:<8}")

    # Show rules with errors if any
    if error_rules_details:
        print(f"\nRULES WITH ERRORS:")
        print(f"{'Rule File':<50} {'Title':<60}")
        print(f"{'-'*112}")
        for rule in error_rules_details:
            filename = rule["filename"][:47] + "..." if len(rule["filename"]) > 50 else rule["filename"]
            title = rule["title"][:57] + "..." if len(rule["title"]) > 60 else rule["title"]
            print(f"{filename:<50} {title:<60}")


if __name__ == "__main__":
    main()