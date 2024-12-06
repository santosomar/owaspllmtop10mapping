# Mapping OWASP Top 10 for LLMs to CVEs and CWEs

This document maps the [OWASP Top 10 for Large Language Model Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/#) to related Common Vulnerabilities and Exposures ([CVEs](https://cve.mitre.org/)) and Common Weakness Enumeration ([CWEs](https://cwe.mitre.org/)). Given the novel nature of LLMs, direct CVE matches were not found at this stage, but relevant CWEs can provide insights into the types of weaknesses these vulnerabilities may exploit.

## LLM01: Prompt Injection

- **[CWE-77](https://cwe.mitre.org/data/definitions/77.html)**: Improper Neutralization of Special Elements used in a Command ('Command Injection')
- **[CWE-94](https://cwe.mitre.org/data/definitions/94.html)**: Improper Control of Generation of Code ('Code Injection')

## LLM02: Sensitive Information Disclosure

- **[CWE-200](https://cwe.mitre.org/data/definitions/200.html)**: Exposure of Sensitive Information to an Unauthorized Actor

## LLM03: Supply-Chain Vulnerabilities

- **[CWE-829](https://cwe.mitre.org/data/definitions/829.html)**: Inclusion of Functionality from Untrusted Control Sphere
- **[CWE-937](https://cwe.mitre.org/data/definitions/937.html)**: Using Components with Known Vulnerabilities

## LLM04: Data and Model Poisoning 

- **[CWE-506](https://cwe.mitre.org/data/definitions/506.html)**: Embedded Malicious Code
- **[CWE-915](https://cwe.mitre.org/data/definitions/915.html)**: Improperly Controlled Modification of Dynamically-Determined Object Attributes

## LLM05: Improper Output Handling

- **[CWE-79](https://cwe.mitre.org/data/definitions/79.html)**: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- **[CWE-116](https://cwe.mitre.org/data/definitions/116.html)**: Improper Encoding or Escaping of Output

## LLM06: Excessive Agency

- **[CWE-250](https://cwe.mitre.org/data/definitions/250.html)**: Execution with Unnecessary Privileges
- **[CWE-266](https://cwe.mitre.org/data/definitions/266.html)**: Incorrect Privilege Assignment
- **[CWE-274](https://cwe.mitre.org/data/definitions/274.html)**: Improper Handling of Insufficient Privileges
- **[CWE-648](https://cwe.mitre.org/data/definitions/648.html)**: Incorrect Use of Privileged APIs
- **[CWE-807](https://cwe.mitre.org/data/definitions/807.html)**: Reliance on Untrusted Inputs in a Security Decision
- No direct CVE mapping available.

## LLM07: System Prompt Leakage

- **[CWE-359](https://cwe.mitre.org/data/definitions/359.html)**: Exposure of Private Personal Information to an Unauthorized Actor

## LLM08: Vector and Embedding Weaknesses 

- **[CWE-807](https://cwe.mitre.org/data/definitions/807.html)**: Reliance on Untrusted Inputs in a Security Decision
- No direct CVE mapping available.

## LLM09: Misinformation 

- No direct CVE/CWE mapping available.

## LLM10: Unbounded Consumption
- **[CWE-770](https://cwe.mitre.org/data/definitions/770.html)**: Allocation of Resources Without Limits or Throttling
- **[CWE-799](https://cwe.mitre.org/data/definitions/799.html)**: Improper Control of Interaction Frequency

**Note**: Identifying specific CVE entries for LLM vulnerabilities is challenging due to the specificity of CVEs to software products or systems. However, the listed CWE entries provide a framework for understanding the types of weaknesses these vulnerabilities might exploit.
