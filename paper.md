---
title: 'logSpecter: A Schema-Aware Secret Scanner for Multi-Gigabyte Cloud Logs'
tags:
  - Python
  - cybersecurity
  - DevSecOps
  - log analysis
  - secret scanning
authors:
  - name: Runze Zhu
    orcid: 0000-0000-0000-0000
    affiliation: 1
affiliations:
 - name: Rochester Institute of Technology, United States
   index: 1
date: 3 September 2026
bibliography: paper.bib
---

# Summary

Cloud environments generate massive volumes of structured JSON logs (e.g., AWS CloudTrail, GCP Audit Logs). Accidental leakage of credentials within these logs is a critical security risk. `logSpecter` is a lightweight Python command-line tool designed to detect leaked secrets in such environments. It streams multi-gigabyte log files line-by-line, parsing nested JSON structures to report the exact schema path of a detected secret. By utilizing a hybrid detection engine, it minimizes both memory footprint and false positives, providing actionable context for DevSecOps teams.

# Statement of need

Standard secret scanning tools, such as Gitleaks [@gitleaks] and Trufflehog [@trufflehog], are predominantly optimized for scanning source code repositories. When applied to massive, semi-structured cloud log dumps, these tools encounter two primary limitations:

1. **Memory Exhaustion & Context Loss**: Loading multi-gigabyte JSON arrays into memory often results in fatal memory exhaustion. Furthermore, traditional scanners report the raw string match without contextualizing its location within the JSON hierarchy, making triage exceptionally difficult. 
2. **False Positive Noise**: Relying purely on regular expressions generates excessive false positives on custom tokens, while pure entropy-based scanning frequently flags benign high-entropy identifiers like UUIDs and cryptographic hashes.

`logSpecter` addresses these challenges by implementing a streaming JSON parser that maintains a constant memory footprint (typically under 50MB) regardless of the log file size. As it traverses the data, it records the dot-notation key path (e.g., `events[0].responseElements.credentials.accessKeyId`), providing precise structural coordinates for every finding. 

For detection, the tool employs a hybrid algorithm that applies high-confidence regular expressions alongside Shannon entropy scoring [@shannon1948]. It dynamically filters out standard UUID and hash formats to reduce noise while successfully catching anomalous, high-entropy secrets. Finally, `logSpecter` exports findings in the Static Analysis Results Interchange Format (SARIF), allowing seamless integration into automated DevSecOps CI/CD pipelines.

# Acknowledgements

We acknowledge the open-source cybersecurity community for foundational tooling and feedback that inspired the creation of logSpecter.

# References
