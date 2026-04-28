# CloudTrail Analyzer Sample Data

`sample_cloudtrail.json` is synthetic CloudTrail-style data that intentionally triggers every Phase 9 detection:

- CT-001 root account usage
- CT-002 console login failure burst
- CT-003 console login from a new country
- CT-004 privilege escalation sequence
- CT-005 mass resource deletion
- CT-006 disabled logging
- CT-007 unauthorized API call burst
- CT-008 new IAM user creation
