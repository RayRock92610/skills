
## 2024-05-24 - Missing Input Length Limits
**Vulnerability:** String fields inside JSON payloads did not have length restrictions. Even with an overall payload size limit, large strings within a parsed JSON array could potentially consume disproportionate memory or processing time in downstream systems.
**Learning:** A global payload size limit is a good first step, but defense-in-depth requires validating the size/length of individual data fields (like strings and arrays) before they are processed further.
**Prevention:** Enforce strict maximum lengths for all string inputs during validation (e.g., maximum 2048 characters for deep links and IDs).
