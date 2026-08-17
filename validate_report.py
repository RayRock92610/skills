import json
import re

def validate_report(report_data):
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

    except json.JSONDecodeError as e:
        print(f"JSON Decode Error: {e}")
        return False
    except Exception as e:
        print(f"Unexpected Error: {e}")
        return False
