import json
import re
import urllib.parse

def validate_report(report_data):
    # Security: Limit input size to prevent DoS attacks (max 1MB)
    MAX_PAYLOAD_SIZE = 1048576
    MAX_ITEMS = 1000

    if not isinstance(report_data, str):
        print("Error: Invalid input type.")
        return False

    if len(report_data) > MAX_PAYLOAD_SIZE:
        print("Error: Payload too large.")
        return False

    try:
        data = json.loads(report_data)
        if not isinstance(data, list):
            print("Error: Report must be a list of items.")
            return False

        # Security: Limit the number of items to prevent CPU exhaustion DoS attacks
        if len(data) > MAX_ITEMS:
            print("Error: Too many items in the report.")
            return False

        required_fields = {
            "id": str,
            "confidence": int,
            "deepLink": str
        }

        for index, item in enumerate(data):
            if not isinstance(item, dict):
                print(f"Error at index {index}: Item must be a dictionary.")
                return False

            # Security: Strict schema enforcement to prevent mass assignment/prototype pollution
            if set(item.keys()) != set(required_fields.keys()):
                print(f"Error at index {index}: Unexpected fields present in item.")
                return False

            for field, field_type in required_fields.items():
                if field not in item:
                    print(f"Error at index {index}: Missing required field '{field}'.")
                    return False

                # Security: Use strict type checking to prevent bool bypassing int checks (bool is a subclass of int)
                if type(item[field]) is not field_type:
                    print(f"Error at index {index}: Field '{field}' must be of type {field_type.__name__}.")
                    return False

                if field_type == str:
                    max_len = 128 if field == "id" else 2048
                    if len(item[field]) > max_len:
                        print(f"Error at index {index}: Field '{field}' exceeds maximum length of {max_len} characters.")
                        return False


            if item["confidence"] not in [1, 2, 3]:
                print(f"Error at index {index}: Confidence must be an integer between 1 and 3.")
                return False

            # Security: Prevent XSS and injection by strict allow-listing ID characters
            if not re.match(r'^[a-zA-Z0-9_.-]+\Z', item["id"]):
                print(f"Error at index {index}: Field 'id' contains invalid characters.")
                return False

            # Security: Use \Z for end of string and avoid loose catch-alls to prevent SSRF via authority manipulation or CRLF
            # Security: Prevent ReDoS by ensuring path components don't overlap with repository names
            if not re.match(r'^https://github\.com/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+(?:[/?#][^\s@<>"\'\\]*)?\Z', item["deepLink"]):
                print(f"Error at index {index}: deepLink must be a valid GitHub URL.")
                return False

            # Security: Prevent path traversal in URLs (including multiple URL-encoded variations)
            decoded_url = item["deepLink"]
            while True:
                unquoted = urllib.parse.unquote(decoded_url)
                if unquoted == decoded_url:
                    break
                decoded_url = unquoted

            if ".." in decoded_url:
                print(f"Error at index {index}: deepLink contains path traversal characters.")
                return False

        print("Validation successful!")
        return True

    except json.JSONDecodeError:
        # Security: Do not expose raw exception details
        print("Error: Invalid JSON format.")
        return False
    except Exception:
        # Security: Do not expose raw exception details
        print("Error: An unexpected error occurred.")
        return False
