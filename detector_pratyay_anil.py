import csv
import json
import re
import sys

# --- PII Definitions based on the challenge description ---

# A. PII (Standalone): Regex patterns for data that is always PII.
# We tie these to specific keys to reduce false positives.
STANDALONE_PII_REGEX = {
    'phone': re.compile(r'^\d{10}$'),
    'aadhar': re.compile(r'^\d{12}$'),
    'passport': re.compile(r'^[A-Z]\d{7}$'),
    'upi_id': re.compile(r'^[\w\.\-]+@[\w]+$')
}

# B. PII (Combinatorial): Keys that contribute to combinatorial PII detection.
COMBINATORIAL_PII_KEYS = [
    'name', 'first_name', 'last_name', 'email', 'address', 'ip_address', 'device_id'
]


def redact_value(key, value):
    """
    Redacts a given value based on its PII type (identified by its key).
    Returns the redacted string.
    """
    value_str = str(value)
    if key in ['phone', 'aadhar']:
        # Redact middle digits, leaving first and last 2 visible
        return value_str[:2] + 'X' * (len(value_str) - 4) + value_str[-2:]
    if key == 'passport':
        return value_str[0] + 'X' * (len(value_str) - 3) + value_str[-2:]
    if key == 'upi_id':
        parts = value_str.split('@')
        if len(parts) == 2:
            user, domain = parts
            return user[:2] + 'X' * (len(user) - 2) + '@' + domain
        return '[REDACTED_UPI]'
    if key in ['name', 'first_name', 'last_name']:
        parts = value_str.split()
        return ' '.join([p[0] + 'X' * (len(p) - 1) if len(p) > 1 else p for p in parts])
    if key == 'email':
        parts = value_str.split('@')
        if len(parts) == 2:
            user, domain = parts
            return user[:2] + '*' * (len(user) - 2) + '@' + domain
        return '[REDACTED_EMAIL]'
    if key == 'address':
        return '[REDACTED_ADDRESS]'
    if key == 'ip_address':
        return '[REDACTED_IP]'
    if key == 'device_id':
        return '[REDACTED_DEVICE_ID]'
    return '[REDACTED]'


def process_record(data_str):
    """
    Detects and redacts PII in a single JSON data string from the CSV.
    
    Args:
        data_str (str): The raw JSON string from the 'data_json' column.

    Returns:
        A tuple containing:
        - redacted_data (dict): A dictionary with PII values redacted.
        - is_pii (bool): True if PII was detected, otherwise False.
    """
    try:
        # The CSV data has escaped quotes (""), replace with a single quote (")
        # to make it a valid JSON string for parsing.
        if data_str.startswith('"') and data_str.endswith('"'):
            data_str = data_str[1:-1]
        valid_json_str = data_str.replace('""', '"')
        data = json.loads(valid_json_str)
    except (json.JSONDecodeError, AttributeError):
        return {}, False # Return empty for malformed records

    redacted_data = data.copy()
    is_pii = False
    pii_keys_to_redact = set()

    # 1. Check for Standalone PII (Always PII)
    for key, value in data.items():
        if key in STANDALONE_PII_REGEX and isinstance(value, str):
            if STANDALONE_PII_REGEX[key].match(value):
                is_pii = True
                pii_keys_to_redact.add(key)

    # 2. Check for Combinatorial PII (PII if >= 2 types are present)
    combinatorial_types_found = set()
    
    # A full name or first/last name pair counts as one "name" type
    if ('name' in data and data.get('name') and len(str(data.get('name')).split()) > 1):
        combinatorial_types_found.add('name')
    elif ('first_name' in data and data.get('first_name') and 'last_name' in data and data.get('last_name')):
        combinatorial_types_found.add('name')
        
    if 'email' in data and data.get('email'):
        combinatorial_types_found.add('email')
    if 'address' in data and data.get('address'):
        combinatorial_types_found.add('address')
    if 'ip_address' in data and data.get('ip_address'):
        combinatorial_types_found.add('ip_address')
    if 'device_id' in data and data.get('device_id'):
        combinatorial_types_found.add('device_id')
        
    if len(combinatorial_types_found) >= 2:
        is_pii = True
        # If combinatorial PII is found, mark all corresponding keys for redaction
        if 'name' in combinatorial_types_found:
             if 'name' in data: pii_keys_to_redact.add('name')
             if 'first_name' in data: pii_keys_to_redact.add('first_name')
             if 'last_name' in data: pii_keys_to_redact.add('last_name')
        if 'email' in combinatorial_types_found and 'email' in data: pii_keys_to_redact.add('email')
        if 'address' in combinatorial_types_found and 'address' in data: pii_keys_to_redact.add('address')
        if 'ip_address' in combinatorial_types_found and 'ip_address' in data: pii_keys_to_redact.add('ip_address')
        if 'device_id' in combinatorial_types_found and 'device_id' in data: pii_keys_to_redact.add('device_id')
            
    # 3. Perform Redaction if PII was detected
    if is_pii:
        for key in pii_keys_to_redact:
            if key in redacted_data:
                redacted_data[key] = redact_value(key, redacted_data[key])
    
    return redacted_data, is_pii


def main(input_file, output_file):
    """Main function to read, process, and write the CSV."""
    try:
        with open(input_file, mode='r', encoding='utf-8') as infile, \
             open(output_file, mode='w', encoding='utf-8', newline='') as outfile:

            reader = csv.reader(infile)
            writer = csv.writer(outfile)

            # Write header for the output file
            writer.writerow(['record_id', 'redacted_data_json', 'is_pii'])

            next(reader) # Skip header of the input file

            for row in reader:
                if len(row) != 2:
                    continue # Skip malformed rows
                record_id, data_json_str = row
                
                redacted_data, is_pii = process_record(data_json_str)

                # Convert redacted dict back to a JSON string for the output CSV.
                redacted_json_output = json.dumps(redacted_data)

                writer.writerow([record_id, redacted_json_output, is_pii])

        print(f"✅ Processing complete. Output written to {output_file}")

    except FileNotFoundError:
        print(f"❌ Error: Input file not found at {input_file}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ An unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 detector_gemini_solution.py <input_csv_file>")
        sys.exit(1)
    
    input_csv_path = sys.argv[1]
    # Set the output file name as required
    output_csv_path = "redacted_output_gemini_solution.csv"
    main(input_csv_path, output_csv_path)
