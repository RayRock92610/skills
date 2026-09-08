
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
