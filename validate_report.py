import json
import re

def validate_report(report_data):
    # Security: Limit input size to prevent DoS attacks (max 1MB)
    MAX_PAYLOAD_SIZE = 1048576

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

        required_fields = {
            "id": str,
            "confidence": int,
            "deepLink": str
        }

        for index, item in enumerate(data):
            for field, field_type in required_fields.items():
                if field not in item:
                    print(f"Error at index {index}: Missing required field '{field}'.")
                    return False

                if not isinstance(item[field], field_type):
                    print(f"Error at index {index}: Field '{field}' must be of type {field_type.__name__}.")
                    return False

            if item["confidence"] not in [1, 2, 3]:
                print(f"Error at index {index}: Confidence must be an integer between 1 and 3.")
                return False

            if not re.match(r'^https://github\.com/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+.*$', item["deepLink"]):
                print(f"Error at index {index}: deepLink must be a valid GitHub URL.")
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
