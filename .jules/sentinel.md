[Output truncated for brevity]

 to enforce a strict schema and didn't validate the characters allowed in the `id` string field. This allowed for potential XSS or other injection attacks via the `id` field and the inclusion of unexpected extra fields (mass assignment / prototype pollution risks).
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

## 2024-05-25 - Path Traversal Bypass via Multiple URL Encoding
**Vulnerability:** The validation logic checking for path traversal characters (`..`) in URLs was performed by decoding the URL exactly once. This allowed an attacker to bypass the check by URL-encoding the dots multiple times (e.g., `%252e%252e` for double encoding). Downstream systems that process and evaluate the URL would often recursively decode the string, re-enabling the path traversal exploit.
**Learning:** Security validations (like looking for malicious substrings) must always occur on fully canonicalized or decoded forms of input data. If data is encoded (e.g., URL-encoded, Base64), pattern matching on the string after a single decode is insufficient because the malicious payload might be nested in multiple encodings.
**Prevention:** Always iteratively decode and canonicalize inputs (e.g., using a while loop with `urllib.parse.unquote()` for URLs until the output doesn't change) *before* performing security validation checks against bad characters or patterns.

## 2026-09-19 - SSRF and CRLF Regex Bypass via URL Encoding
**Vulnerability:** The regular expression used to validate `deepLink` GitHub URLs was executed against the raw, URL-encoded input strings, while downstream systems decode the URL before processing. This allowed an attacker to bypass SSRF or CRLF validation by URL-encoding restricted characters (e.g., `%40` for `@` or `%0a` for a newline).
**Learning:** Security validations (like regular expressions enforcing allowed formats or blocking specific characters) must always occur on canonicalized or decoded forms of input data. If data is encoded, pattern matching on the raw string is insufficient because the encoding obfuscates the malicious payload.
**Prevention:** Always iteratively decode and canonicalize inputs (e.g., using a while loop with `urllib.parse.unquote()` for URLs until the output doesn't change) *before* performing security validation checks, including regex matching.

## 2024-09-25 - Command Injection Risks in Documentation Examples
**Vulnerability:** Found hardcoded plaintext passwords in shell CLI commands (e.g., `--password=PASSWORD`, `psql "host=127.0.0.1 password=PASSWORD"`) within documentation.
**Learning:** Examples in documentation are frequently copy-pasted into terminal sessions. Passing passwords via command line flags causes the password to be written in plaintext to the user's shell history (e.g., `.bash_history`) and temporarily exposes it to process-listing tools (e.g., `ps`).
**Prevention:** In documentation for command-line interfaces, always recommend secure mechanisms for providing secrets, such as interactive prompts (e.g., `--prompt-for-password`), environment variables, or dedicated secret files. Avoid using CLI flags that accept secrets directly.

## 2026-09-26 - Command Line Vulnerabilities in Documentation Examples for AlloyDB
**Vulnerability:** Found hardcoded plaintext passwords in shell CLI commands for AlloyDB clusters creation (e.g., `--password=PASSWORD`, `--password=YOUR_SECURE_PASSWORD`) within documentation.
**Learning:** Examples in documentation are frequently copy-pasted into terminal sessions. Passing passwords via command line flags causes the password to be written in plaintext to the user's shell history (e.g., `.bash_history`) and temporarily exposes it to process-listing tools (e.g., `ps`).
**Prevention:** In documentation for command-line interfaces like `gcloud alloydb`, always recommend secure mechanisms for providing secrets, such as interactive prompts (e.g., `--prompt-for-password`), environment variables, or dedicated secret files. Avoid using CLI flags that accept secrets directly.

## 2026-10-27 - Airflow Traceback Leakage / Logging Raw Exceptions
**Vulnerability:** Raw external API exceptions were being printed directly into logs (e.g., `logging.error("External API request failed: %s", e)` and re-raising without `from None`). This exposed sensitive information like API credentials, authorization info, and request details.
**Learning:** In Python, implicitly chained exceptions or logging raw exception objects serialize the full traceback and local variables into logs, which can leak secrets.
**Prevention:** Catch external exceptions explicitly, sanitize the log message (`logging.error("External API request failed - check external error tracker")`), and suppress implicit exception chaining by using `raise ... from None`. An automated AST rule now validates this.

## 2024-10-02 - AST Security Scanner Bypass via Renaming Exception Variable
**Vulnerability:** The AST security scanner `ast_security_scanner.py` responsible for preventing raw exception leakage (like `logging.error(e)`) was only checking for the variable name `"e"`. If an engineer used a different exception variable name (e.g., `except Exception as err: logging.error(err)`), the scanner failed to detect the leakage, exposing a bypass to a security control.
**Learning:** Hardcoded literal comparisons for variable names in static analysis tools are ineffective because developers can use arbitrary naming conventions. AST rules must dynamically track aliases and bound names from scopes (like `except` handler variable names) to accurately trace data flow.
**Prevention:** Update `ast_security_scanner.py` to keep a stack of dynamically captured variable names from `visit_ExceptHandler`'s `node.name` field, checking against those dynamically scoped names instead of just hardcoded strings.

### AST Exception Chaining & Traceback Leakage Enforcement
- **Vulnerability**: `ast_security_scanner.py` failed to detect chained traceback leaks (`raise ... from e`) and falsely flagged legitimate bare `raise` statements.
- **Root Cause**: Missing check for `node.exc is None` penalized standard error re-raising; node cause evaluation did not validate `isinstance(node.cause, ast.Constant) and node.cause.value is None`.
- **Enforced Policy**:
  - `raise` (bare): Allowed for bubbling current context.
  - `raise CustomError(...) from None`: Allowed; tracebacks explicitly suppressed.
  - `raise CustomError(...) from e`: Flagged; leaks internal tracebacks across boundaries.
  - `raise CustomError(...)`: Flagged; unsuppressed exception creation.
- **Task ID**: 15748934047169564082
