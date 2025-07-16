import os
import yaml

# Define the folder where sigma rules are stored
# RULES_PATH = "path/to/your/folder"
RULES_PATH = "../rules"

# Define the threats you want to search for rules.
# All values must follow sigma tags taxonomy: https://github.com/SigmaHQ/sigma-specification/blob/main/appendix/sigma-tags-appendix.md
GROUPS = ["g0091"] # example: g0018
TOOLS = ["s0139"] # example: s0066
CVES = ["cve.2021-1675"] # example: cve.2021-1678
TACTICS = [] # example: discovery
TECHNIQUES = [] # example: t1012

def search_yaml_files():
    """
    Walk through the directory structure starting at root_directory,
    open YAML files (.yml or .yaml), and check if the "tags" key contains
    any of the specified threats.
    """
    for dirpath, _, filenames in os.walk(RULES_PATH):
        for filename in filenames:
            if filename.lower().endswith(('.yml', '.yaml')):
                filepath = os.path.join(dirpath, filename)
                try:
                    with open(filepath, "r", encoding="utf-8") as file:
                        data = yaml.safe_load(file)
                except yaml.YAMLError as err:
                    print(f"Error parsing YAML in {filepath}: {err}")
                    continue
                except Exception as e:
                    print(f"Error reading file {filepath}: {e}")
                    continue

                # Retrieve the "tags" from the YAML data.
                # The "tags" field is a list.
                tags = data.get("tags", [])
                if not isinstance(tags, list):
                    # If "tags" is not a list at this point, skip the file.
                    continue

                # Check if any of the search terms exist in the tags list.
                msg = []
                for group in GROUPS:
                    if "attack." + group in tags:
                        msg.append(f'Group: {group}')
                for tool in TOOLS:
                    if "attack." + tool in tags:
                        msg.append(f'Tool: {tool}')
                for cve in CVES:
                    if cve in tags:
                        msg.append(f'CVE: {cve}')
                for tactic in TACTICS:
                    if "attack." + tactic in tags:
                        msg.append(f'Tactic: {tactic}')
                for technique in TECHNIQUES:
                    if "attack." + technique in tags:
                        msg.append(f'Technique: {technique}')
                if msg:
                    print(f"Match in: {filepath}")
                    print(f"The following threats have been found: {', '.join(msg)}")
                    print("Content:")
                    print(yaml.dump(data, default_flow_style=False, sort_keys=False))
                    print("-" * 40)


if __name__ == "__main__":
    # Check if any search terms are provided
    search_terms = GROUPS + TOOLS + CVES + TACTICS + TECHNIQUES
    if not search_terms:
        print("No threats provided. Please specify at least one threat.")
    else:
        print(f"Searching for tags: {search_terms}")

        # Call the function to search for YAML files containing the specified tags
        search_yaml_files()

