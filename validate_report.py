import json
import re
import urllib.parse
from urllib.parse import urlsplit

def check_depth(obj, depth=0, max_depth=10):
    if depth > max_depth:
        return False
    if isinstance(obj, dict):
        return all(check_depth(v, depth + 1, max_depth) for v in obj.values())
    elif isinstance(obj, list):
        return all(check_depth(v, depth + 1, max_depth) for v in obj)
    return True

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

        # Security: Prevent JSON recursion depth attacks (e.g. nested lists/dicts bomb)
        if not check_depth(data):
            print("Error: JSON payload is too deeply nested.")
            return False

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

            # Security: Prevent path traversal in URLs (including multiple URL-encoded variations)
            # Security: Always decode first to prevent validation bypass via URL encoding
            decoded_url = item["deepLink"]
            while True:
                unquoted = urllib.parse.unquote(decoded_url)
                if unquoted == decoded_url:
                    break
                decoded_url = unquoted

            # 1. Reject control characters, carriage returns, and null bytes upfront
            if any(ord(c) < 32 or ord(c) == 127 for c in decoded_url):
                print(f"Error at index {index}: deepLink contains control characters.")
                return False

            if ".." in decoded_url:
                print(f"Error at index {index}: deepLink contains path traversal characters.")
                return False

            try:
                parsed = urlsplit(decoded_url)
            except ValueError:
                print(f"Error at index {index}: deepLink could not be parsed.")
                return False

            ALLOWED_SCHEMES = {"https"}
            ALLOWED_DOMAINS = {"github.com"}

            # 2. Strict scheme allowlisting (blocks file://, javascript:, data:, gopher://)
            if parsed.scheme.lower() not in ALLOWED_SCHEMES:
                print(f"Error at index {index}: deepLink scheme is not allowed.")
                return False

            # 3. Prevent userinfo injection (e.g., https://legit.com@attacker.com)
            if parsed.username or parsed.password:
                print(f"Error at index {index}: deepLink contains embedded credentials.")
                return False

            # 4. Host validation: prevent domain confusion and trailing dot bypasses
            hostname = (parsed.hostname or "").lower().rstrip(".")
            if not hostname or hostname not in ALLOWED_DOMAINS:
                print(f"Error at index {index}: deepLink domain is not allowed.")
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
