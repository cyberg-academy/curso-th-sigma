import requests
from datetime import datetime
import json

# URLs for threats and tools (source ThaiCERT
THREATS_URL = "https://apt.etda.or.th/cgi-bin/getcard.cgi?g=all&o=j"
TOOLS_URL   = "https://apt.etda.or.th/cgi-bin/getcard.cgi?t=all&o=j"


def download_threats() -> list[dict]:
    """
    Downloads the threats data from the specified URL.
    """
    try:
        resp_threats = requests.get(THREATS_URL)
        return resp_threats.json()["values"]
    except Exception as e:
        print("Error downloading threats data:", e)
        exit()

def download_tools() -> list[dict]:
    """
    Downloads the tools data from the specified URL.
    """
    try:
        resp_tools = requests.get(TOOLS_URL)
        # (2025/04/15) There is an error in the tools JSON, lack of "" in one reference of a list of strings: "last-db-change": "2025-03-02", let's solve it:
        # return resp_tools.json()["values"]
        content = resp_tools.text.replace('https://screenconnect.connectwise.com/', '"https://screenconnect.connectwise.com/"')
        return json.loads(content)["values"]
    except Exception as e:
        print("Error downloading tools data:", e)
        exit()

def get_uniq_sectors_countries(threats_data: list[dict]) -> (list[str], list[str]):
    """
    Extracts unique sectors and countries from the threats data.
    Returns two sorted lists: sectors and countries.
    """
    all_sectors = set()
    all_countries = set()

    for item in threats_data:
        if item.get("observed-sectors"):
            for sector in item.get("observed-sectors", []):
                all_sectors.add(sector)
        if item.get("observed-countries"):
            for country in item.get("observed-countries", []):
                all_countries.add(country)

    return sorted(list(all_sectors)), sorted(list(all_countries))

def normalize_date(date_str: str) -> str:
    """
    Returns a normalized date string in "YYYY-MM" format.
    Handles:
      - Year only strings, e.g. "2007" => "2007-01"
      - Ranges, e.g. "2008/2014" => "2014-01"
      - Strings with descriptors, e.g. "2016 Summer" => "2016-07"
      - Already correctly formatted "YYYY-MM" strings
    """
    if not date_str or date_str.strip() == "":
        return ""

    date_str = date_str.strip()

    # If the date is a range like "2008/2014", take the last part.
    if "/" in date_str:
        date_str = date_str.split("/")[1].strip()

    # Check if there is a descriptor by testing for a space.
    if " " in date_str:
        parts = date_str.split()
        # Assume the first part is the year and the second part is a descriptor.
        year = parts[0]
        descriptor = parts[1].lower()
        # Mapping for textual descriptors to month numbers.
        descriptor_to_month = {
            "early": "01",   # beginning of the year
            "spring": "04",  # April approximates spring
            "mid":    "06",  # mid-year
            "summer": "07",  # summer
            "autumn": "10",  # fall/autumn
            "late":   "12"   # end of the year
        }
        month = descriptor_to_month.get(descriptor, "01")
        return f"{year}-{month}"

    # If the string is only a year, append "-01"
    if len(date_str) == 4 and date_str.isdigit():
        return f"{date_str}-01"

    # Otherwise, assume the date is already in the "YYYY-MM" format.
    return date_str

def get_risk_category(last_campaign_date_str: str) -> (str, str):
    """
    Determines the risk category based on the last campaign date.
    """
    try:
        # Assuming the date format is YYYY-MM
        last_campaign_date_str = normalize_date(last_campaign_date_str)
        last_campaign_date = datetime.strptime(last_campaign_date_str, "%Y-%m")
    except Exception:
        # If date is missing or format is not as expected, treat it as LOW risk.
        return "LOW", ""

    now = datetime.now()
    diff_days = (now - last_campaign_date).days

    if diff_days < 365:
        return "HIGH", last_campaign_date_str      # Recent campaign (< 1 year)
    elif 365 <= diff_days < 3 * 365:
        return "MEDIUM", last_campaign_date_str    # Campaign between 1 and 3 years
    else:
        return "LOW", last_campaign_date_str       # Older than 3 years

# Filtering function for both threats and tools.
def filter_items(threats: list, tools: list, selected_sectors: set, selected_countries: set) -> list[dict]:
    filtered = []
    for item in threats:
        # Get the list of sectors and countries for the item. Default to empty list if missing.
        item_sectors = set(item.get("observed-sectors", []))
        item_countries = set(item.get("observed-countries", []))
        # Check whether there is any overlap with the company-related sectors/countries.
        if item_sectors.intersection(selected_sectors) and item_countries.intersection(selected_countries):
            # Determine the risk category using the campaign date.
            last_campaign = item.get("operations", [])
            last_campaign = last_campaign[-1]["date"] if last_campaign else []
            risk, last_campaign_date = get_risk_category(last_campaign) if last_campaign else ("LOW", "")
            filtered_actor = {
                "name": item.get("actor", "Unknown"),
                "risk": risk,
                "last_campaign_date": last_campaign_date,
                "actor_data": item,
            }
            actor_tools = {}
            for actor_tool in item.get("tools", []):
                for tool in tools:
                    tools_names = [tool_name["name"].lower() for tool_name in tool.get("names", [])]
                    if actor_tool.lower() in tools_names:
                        actor_tools[actor_tool] = tool
                        break
            if actor_tools:
                filtered_actor["tools_used_by_actor"] = actor_tools
            filtered.append(filtered_actor)
    return filtered


if __name__ == "__main__":
    # Download threats and tools
    print("\nFetching threats ...")
    threats_data = download_threats()
    print("Done!\n")
    print("Fetching tools ...")
    tools_data = download_tools()
    print("Done!\n")

    # Get unique sectors and countries from the threats data.
    all_sectors, all_countries = get_uniq_sectors_countries(threats_data)
    # Show available options for sectors and countries and Ask the user to input desired sectors and countries to check.
    print("Available sectors:")
    for sector in all_sectors:
        print(" -", sector)
    selected_sectors_input = input("\nEnter the sectors related to your company (comma separated): ")
    print("\nAvailable countries:")
    for country in all_countries:
        print(" -", country)
    selected_countries_input = input("\nEnter the countries where your company operates (comma separated): ")

    # Create sets of the user-selected sectors and countries (cleaning spaces).
    selected_sectors = {s.strip() for s in selected_sectors_input.split(",") if s.strip()}
    selected_countries = {c.strip() for c in selected_countries_input.split(",") if c.strip()}

    affecting_threats = filter_items(threats_data, tools_data, selected_sectors, selected_countries)

    # Group items by their risk level.
    risk_groups = {"HIGH": [], "MEDIUM": [], "LOW": []}
    for item in affecting_threats:
        risk_groups[item["risk"]].append(item)

    # Print the results in risk order.
    print("\nActors and Tools that may be interested in attacking the company (based on past campaigns):")
    print("\nHIGH risk (Actors with recent campaigns date, < 1 year):")
    if risk_groups["HIGH"]:
        for item in risk_groups["HIGH"]:
            print(f" - {item['name']} (Last Campaign: {item['last_campaign_date']})")
            print(f"Actor data: {json.dumps(item['actor_data'], indent=4)}")
            print(f"Tools used by actor: {json.dumps(item['tools_used_by_actor'], indent=4) if item.get('tools_used_by_actor') else 'None'}")
    else:
        print(" - None actors found with HIGH risk.")

    print("\nMEDIUM risk (Actors with campaigns date between 1 and 3 years age):")
    if risk_groups["MEDIUM"]:
        for item in risk_groups["MEDIUM"]:
            print(f" - {item['name']} (Last Campaign: {item['last_campaign_date']})")
            print(f"Actor data: {json.dumps(item['actor_data'], indent=4)}")
            print(f"Tools used by actor: {json.dumps(item['tools_used_by_actor'], indent=4) if item.get('tools_used_by_actor') else 'None'}")
    else:
        print(" - None actors found with MEDIUM risk.")

    print("\nLOW risk (Actors wit campaigns older than 3 years or unknown):")
    if risk_groups["LOW"]:
        for item in risk_groups["LOW"]:
            print(f" - {item['name']} (Last Campaign: {item['last_campaign_date']})")
            print(f"Actor data: {json.dumps(item['actor_data'], indent=4)}")
            print(f"Tools used by actor: {json.dumps(item['tools_used_by_actor'], indent=4) if item.get('tools_used_by_actor') else 'None'}")
    else:
        print(" - None actors found with LOW risk.")

    # Save in JSON file too
    with open("threats.json", "w") as f:
        json.dump(risk_groups, f, indent=4)