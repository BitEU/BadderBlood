### Inject 1: Privileged Group Membership Audit
**From:** Security Operations Center (SOC)

**Subject:** URGENT: Suspicious Authentication from Privileged Accounts

Team,

Your SOC has flagged unusual authentication activity originating from accounts that appear to have elevated privileges they should not have. We are concerned an attacker may have already leveraged one or more of these accounts.

Please audit your highest-privilege groups, identify any accounts that do not belong, document what damage they could do, and remediate.

Regards,

**Sherlock Holmes** Incident Response Lead

---

### Inject 2: Domain Root Access Control Audit
**From:** Threat Intelligence Team

**Subject:** DIRECTIVE: Potential Persistence Mechanism Identified on Domain Root

Team,

Our threat intelligence partners have flagged sirshanova.com as potentially having a persistence mechanism in place that does not require malware or elevated credentials to maintain. We believe the mechanism may involve the domain itself as an object.

Please investigate, document your findings in detail, and remediate.

**Fox Mulder** Lead Threat Intelligence Analyst

---

### Inject 3: Kerberoasting Exposure Audit
**From:** Blue Team Operations

**Subject:** ALERT: Active Kerberoasting Attacks Detected

Team,

You are tasked with investigating your domain's exposure to Kerberoasting. Kerberoasting is an offline password cracking technique that requires no special privileges to initiate. Certain account configurations in the domain may make this significantly worse than it needs to be.

Identify your exposure, remediate what you can, and report back.

Best,

**Geralt of Rivia** Blue Team Commander

---

### Inject 4: AS-REP Roasting Vulnerability Investigation
**From:** External Threat Monitoring

**Subject:** INVESTIGATION REQUIRED: AS-REP Roasting Claims

Team,

An anonymous tip claims that sirshanova.com is vulnerable to an attack that allows an unauthenticated attacker to obtain crackable credential material from your domain.

Please investigate whether this claim has merit, identify any affected accounts, remediate, and generate an executive summary of how the attack works and your findings. Forward the summary to the OGC email address.

**Nancy Drew** Risk Management & Investigations

---

### Inject 5: Credential Exposure Investigation
**From:** Threat Intelligence Team

**Subject:** DIRECTIVE: Possible Plaintext Credential Exposure

Team,

Our threat intelligence partners believe sirshanova.com may be configured in ways that expose credentials in plaintext — both at rest and in memory — to low-privilege attackers. At least two distinct misconfigurations are believed to be present.

Audit the environment, remediate all findings, and provide a brief report documenting each issue and how an attacker would exploit it.

**Clarice Starling** Threat Intelligence Analyst

---

### Inject 6: Privileged Group Membership via Group Nesting
**From:** Active Directory Security Architecture

**Subject:** COMPLIANCE NOTICE: Recursive Group Membership Audit

Team,

A recent compliance article has flagged group nesting as a commonly abused persistence and privilege escalation technique in Active Directory environments. We have reason to believe sirshanova.com may be affected.

Produce a two-paragraph report confirming or debunking whether this is a real concern in our environment, enumerate any users impacted, and remediate.

**Christopher Nolan** AD Security Architect

---

### Inject 7: GPO Permission Audit
**From:** Security Operations Center (SOC)

**Subject:** CRITICAL: Anomalous Group Policy Modification Events Detected

Team,

Your SIEM has alerted on unexpected Group Policy modification events in the sirshanova.com domain. We are concerned that accounts without legitimate administrative need may have the ability to modify production policies.

Identify all accounts with policy modification rights that should not have them, document the potential impact of each, and remove those permissions immediately.

**Ellen Ripley** SOC Manager

---

### Inject 8: Local Administrator Credential Exposure and Privilege Escalation Path
**From:** Identity & Access Management (IAM)

**Subject:** MANDATE: Investigate Reported Privilege Escalation Paths Tied to Local Admin Management

Team,

We have received a report that a low-privileged employee was able to obtain local administrator credentials for machines they have no business accessing. A separate report suggests that a routine maintenance process may be exploitable by any domain user.

Investigate both claims, document your findings, remediate, and report back.

**Marty McFly** IAM Director
