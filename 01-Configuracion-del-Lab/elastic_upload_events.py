from dotenv import load_dotenv
import os
from elasticsearch import Elasticsearch
import json
import time
from datetime import datetime, timezone
import re


# Load environment variables from .env file
load_dotenv()
# Start timer
start = time.perf_counter()

# Constants
ELK_HOST = "https://localhost:9200/"
API_KEY = os.getenv("ELASTIC_API_KEY")
if not API_KEY:
    print("API key not found. Please set the ELASTIC_API_KEY environment variable.")
    exit()
TH_LAB_EVENTS_FILE = "cyberg-th-lab-events.json"
ELK_INDEX = "cyberg-th-lab"
MAX_EVENTS_TO_INDEX_PER_REQUEST = 500
# A regular expression that matches date patterns like:
DATE_REGEX = re.compile(
    r'\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}\.\d+(?:Z|[+-]\d{2}:\d{2})?\b'
)

# Start ELK client
elk_client = Elasticsearch(ELK_HOST, api_key=API_KEY, verify_certs=False)

# Check if the connection and auth is successful
indexes = elk_client.ping()
if not indexes:
    print("Elasticsearch is not reachable or auth failed. Check connectivity and credentials.")
    exit()
else:
    print("Connected to Elasticsearch successfully.")

# Read events json file
with open(TH_LAB_EVENTS_FILE, 'r') as file:
    events = json.load(file)

"""START FUNC HELPERS"""
def format_timestamp(dt):
    """
    Convert a datetime object to the desired ISO format: "YYYY-MM-DDTHH:MM:SS.mmmZ".
    The datetime is first converted to UTC.
    """
    return dt.astimezone(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')

def update_fields(obj, new_ts_str):
    """
    Recursively updates any string within the given object (which may be a dict, list, or string)
    by replacing date substrings with the provided new timestamp string.
    """
    if isinstance(obj, str):
        return DATE_REGEX.sub(new_ts_str, obj)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            obj[k] = update_fields(v, new_ts_str)
        return obj
    elif isinstance(obj, list):
        return [update_fields(item, new_ts_str) for item in obj]
    else:
        return obj

def update_record(record, now):
    """
    Updates a single record's '@timestamp' field and any nested strings containing date substrings.

    For each record:
      - If record["@timestamp"] equals the reference timestamp, set it to now.
      - Otherwise, compute delta = (record_timestamp - reference_timestamp) and set new_timestamp = now + delta.

    Then update any matching date substrings in nested string values.
    """
    orig_ts_str = record.get("@timestamp")
    if not orig_ts_str:
        return record  # Nothing to adjust if there's no @timestamp field.

    try:
        record_dt = datetime.strptime(orig_ts_str, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=timezone.utc
        )
    except Exception as e:
        print(f"Error parsing '{orig_ts_str}': {e}")
        return record

    # Calculate the new timestamp: if equal to reference, delta is 0 (new_ts equals now).
    reference_dt = datetime.strptime("2025-04-17T06:49:16.177Z", "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    delta = record_dt - reference_dt
    new_dt = now + delta
    new_ts_str = format_timestamp(new_dt)

    # Update the top-level @timestamp.
    record["@timestamp"] = new_ts_str

    # Recursively update any string values in the record that match a date pattern.
    for key, value in record.items():
        if key == "@timestamp":
            continue  # Skip as it's already updated.
        record[key] = update_fields(value, new_ts_str)

    return record
"""END FUNC HELPERS"""

events_uploaded = 0
now = datetime.now(timezone.utc)
bulk_body = [] # We will index events in bulk to improve performance
for event in events:
    event_time_updated = update_record(event, now)
    bulk_body.append({"create": {"_index": ELK_INDEX}})
    bulk_body.append(event)
i = 0
MAX_EVENTS_TO_INDEX_PER_REQUEST = MAX_EVENTS_TO_INDEX_PER_REQUEST * 2 # because we upload index + event
while i < len(bulk_body):
    request_body = bulk_body[i : i + MAX_EVENTS_TO_INDEX_PER_REQUEST]
    request_size = sum(len(json.dumps(item)) for item in request_body)

    # Check if the request size exceeds 100 MB
    while request_size >= 100 * 1024 * 1024:
        MAX_EVENTS_TO_INDEX_PER_REQUEST //= 2
        request_body = bulk_body[i : i + MAX_EVENTS_TO_INDEX_PER_REQUEST]
        request_size = sum(len(json.dumps(item)) for item in request_body)

    try:
        response = elk_client.bulk(body=request_body)
        body = response.body
        events_uploaded += len(body["items"])
        if body.get("errors"):
            print(f"Errors occurred while indexing events: {body['errors']}")
    except Exception as e:
        print(f"Error indexing events: {e}")
    i += MAX_EVENTS_TO_INDEX_PER_REQUEST


print(f'Total events uploaded: {events_uploaded}')
end = time.perf_counter()
elapsed_seconds = end - start
elapsed_minutes = elapsed_seconds / 60
print(f"Execution time: {elapsed_minutes:.2f} minutes")