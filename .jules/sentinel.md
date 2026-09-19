
## 2024-05-24 - Missing Input Length Limits
**Vulnerability:** String fields inside JSON payloads did not have length restrictions. Even with an overall payload size limit, large strings within a parsed JSON array could potentially consume disproportionate memory or processing time in downstream systems.
**Learning:** A global payload size limit is a good first step, but defense-in-depth requires validating the size/length of individual data fields (like strings and arrays) before they are processed further.
**Prevention:** Enforce strict maximum lengths for all string inputs during validation (e.g., maximum 2048 characters for deep links and IDs).

## 2024-05-24 - SSRF Regex Bypass & Boolean Type Confusion
**Vulnerability:** The regex validating `deepLink` GitHub URLs was overly permissive at the end (`.*$`), allowing SSRF or open redirect payloads like `https://github.com/foo/bar@attacker.com`. Additionally, type checking using `isinstance(value, int)` allowed boolean values to bypass the check, leading to `True` passing as `1` and bypassing further validation constraints.
**Learning:** `.*$` at the end of regex constraints often fails to restrict trailing components, making it susceptible to credential/host injections using `@`. Also, `isinstance()` is unsafe for strict primitive type checking in Python because `bool` is a subclass of `int`.
**Prevention:** Use strictly constrained character sets and `\Z` to enforce string termination in regex validations for URLs. Use `type(value) is expected_type` instead of `isinstance()` when checking primitive fields in loosely-typed payloads like JSON.

## 2024-05-24 - Hardcoded Credentials in Examples and Tests
**Vulnerability:** Hardcoded plaintext passwords found in test files and documentation examples (`password="my-password"`).
**Learning:** Sample code and test code are frequently copy-pasted into production environments by developers. Hardcoded secrets in these areas often propagate insecure default configurations and practices to real-world applications.
**Prevention:** Always use environment variables (`os.environ["DB_PASS"]`) or secure secret managers even in documentation and tests. Mock the environment variables during testing to ensure tests pass without needing real credentials.

## 2024-05-24 - Unvalidated JSON List Items (Type Error / DoS)
**Vulnerability:** When parsing a JSON report list, `validate_report` checked if the payload was a list but failed to ensure that individual items within the list were actually objects/dictionaries before attempting key lookups (`if field not in item`). This allowed an attacker to pass primitive types (like integers, `[1]`) within the array, causing an unhandled `TypeError` (e.g., `argument of type 'int' is not iterable`) during execution, potentially leading to 500 errors or application crashes.
**Learning:** `json.loads` can return varied structures. Just because the outer container is a list does not mean the inner elements are dictionaries, even if your API expects objects. Always validate the type of *each element* inside a list before interacting with its properties or keys.
**Prevention:** Explicitly check if elements in a parsed JSON array are dictionaries (e.g., `isinstance(item, dict)`) before performing dictionary-specific operations or validations.

## 2024-05-24 - Catastrophic Backtracking (ReDoS) in Regex
**Vulnerability:** The regular expression used to validate `deepLink` URLs (`r'^https://github\.com/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+[^\s@<>"\'\\]*\Z'`) was vulnerable to Regular Expression Denial of Service (ReDoS). The combination of `[a-zA-Z0-9_.-]+` (matching repo names) and `[^\s@<>"\'\\]*` (matching the rest of the URL) created overlapping match sets. An attacker could craft a long URL that causes the regex engine to backtrack extensively if it ultimately fails to match `\Z`, hanging the process and causing a Denial of Service.
**Learning:** Overlapping character classes in adjacent quantifiers (`+` followed by `*`) often lead to catastrophic backtracking. Performance testing with long invalid strings is critical for security validation of regex patterns.
**Prevention:** Eliminate ambiguity by clearly separating structural parts of the string. In this case, ensuring that any characters following the repository name must begin with a delimiter (like `/`, `?`, or `#`) prevents overlapping matches and eliminates the ReDoS vulnerability: `(?:[/?#][^\s@<>"\'\\]*)?`.

## 2024-05-24 - Hardcoded Secrets in Infrastructure as Code (IaC) Examples
**Vulnerability:** Hardcoded plaintext passwords (e.g., `password = "changeme"`) found in Terraform documentation examples for Cloud SQL and AlloyDB.
**Learning:** Developers frequently copy and paste Infrastructure as Code examples directly into their modules. Providing hardcoded secrets in documentation encourages deploying databases with weak, known credentials, leading to immediate compromise upon deployment.
**Prevention:** In IaC documentation and templates, always use secret managers or dynamic password generation resources (e.g., Terraform's `random_password`) to ensure secure-by-default behavior when examples are adopted.

## 2024-05-24 - Missing Input Validation on User Data
**Vulnerability:** The JSON validation logic failed to enforce a strict schema and didn't validate the characters allowed in the `id` string field. This allowed for potential XSS or other injection attacks via the `id` field and the inclusion of unexpected extra fields (mass assignment / prototype pollution risks).
**Learning:** Validating just the types and lengths of required fields is insufficient. You must explicitly restrict the character set for string fields (especially identifiers) using strict regex allow-listing and enforce the exact expected schema structure.
**Prevention:** Enforce strict schema boundaries by rejecting unexpected fields (e.g., `set(item.keys()) != set(required_fields.keys())`) and use strict regex patterns (e.g., `^[a-zA-Z0-9_.-]+\Z`) to restrict input to only safe characters.

## 2024-05-24 - Missing Array Length Limits
**Vulnerability:** A global payload size limit (e.g., 1MB) was in place, but there was no restriction on the number of elements within a JSON array. An attacker could craft a payload with hundreds of thousands of empty objects `[{}]`, forcing the server to loop excessively and perform expensive validation checks, leading to a CPU exhaustion Denial of Service (DoS).
**Learning:** Limiting the total payload size is necessary but not sufficient. When processing lists or collections, algorithmic complexity vulnerabilities can still occur if the number of elements is unbounded.
**Prevention:** Enforce strict maximum item counts (e.g., `len(data) > MAX_ITEMS`) immediately after verifying an input is an array/list, before iterating over its contents.

## 2024-05-24 - Path Traversal / SSRF via '..' in URLs
**Vulnerability:** The regex used to validate `deepLink` URLs (`r'^https://github\.com/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+...'`) allowed `..` in path components because `.` is included in the allowed character class. This allowed an attacker to craft a payload like `https://github.com/../../etc/passwd`, causing a path traversal vulnerability that could be used for Server-Side Request Forgery (SSRF) or escaping the intended repository scope in downstream processing.
**Learning:** Regex character classes like `[a-zA-Z0-9_.-]` allow sequence patterns like `..` unless explicitly rejected. Validating domain structures requires strict path boundary checks to prevent traversal.
**Prevention:** Explicitly check for and reject the substring `..` in URL inputs, or use URL parsing libraries that enforce safe path resolution before allowing requests.

## 2026-09-19 - Path Traversal Bypass via URL Encoding
**Vulnerability:** The validation logic checking for path traversal characters (`..`) in URLs was performed on raw, URL-encoded input strings. This allowed an attacker to bypass the check by simply URL-encoding the dots (e.g., `%2e%2e` or `%2E%2E`). Downstream systems that process and evaluate the URL would decode the string, re-enabling the path traversal exploit.
**Learning:** Security validations (like looking for malicious substrings) must always occur on canonicalized or decoded forms of input data. If data is encoded (e.g., URL-encoded, Base64), pattern matching on the raw string is insufficient because the encoding obfuscates the malicious payload.
**Prevention:** Always decode and canonicalize inputs (e.g., using `urllib.parse.unquote()` for URLs) *before* performing security validation checks against bad characters or patterns.
