import argparse

# ----------------------------
# Argument Parser
# ----------------------------
parser = argparse.ArgumentParser(
    description="SOC Assistant CLI - Windows Security Events"
)

parser.add_argument(
    "command",
    choices=["explain", "mitre", "severity", "next"],
    help="SOC action to perform"
)

parser.add_argument(
    "event_id",
    help="Windows Event ID (e.g., 4625, 4624, 1102)"
)

args = parser.parse_args()
event = args.event_id

# ----------------------------
# Event Database
# ----------------------------
EVENTS = {
    "4625": {
        "name": "Failed Logon Attempt",
        "mitre": ("T1110", "Brute Force", "Credential Access"),
        "severity": "HIGH",
        "reason": [
            "Repeated authentication failures",
            "Possible brute-force or password spraying attack"
        ],
        "next": [
            "Identify source IP and geolocation",
            "Check failed attempts per account and IP",
            "Analyze logon type (2, 3, 10)",
            "Correlate with successful logons (4624)",
            "Check account lockout events (4740)"
        ]
    },

    "4624": {
        "name": "Successful Logon",
        "mitre": ("T1078", "Valid Accounts", "Initial Access"),
        "severity": "MEDIUM",
        "reason": [
            "Valid authentication occurred",
            "May indicate compromised credentials if suspicious"
        ],
        "next": [
            "Verify logon source and time",
            "Check if preceded by failed logons",
            "Validate user role and behavior",
            "Check logon type (interactive, network, RDP)"
        ]
    },

    "1102": {
        "name": "Security Log Cleared",
        "mitre": ("T1070", "Indicator Removal", "Defense Evasion"),
        "severity": "CRITICAL",
        "reason": [
            "Security logs cleared",
            "Strong indicator of attacker activity"
        ],
        "next": [
            "Identify user who cleared logs",
            "Check recent admin activity",
            "Correlate with privilege escalation events",
            "Escalate incident immediately"
        ]
    },

    "4672": {
        "name": "Special Privileges Assigned",
        "mitre": ("T1068", "Privilege Escalation", "Privilege Escalation"),
        "severity": "HIGH",
        "reason": [
            "Admin-level privileges granted",
            "Potential privilege abuse"
        ],
        "next": [
            "Identify account granted privileges",
            "Verify authorization",
            "Check recent login history",
            "Monitor follow-up activity"
        ]
    },

    "4688": {
        "name": "Process Creation",
        "mitre": ("T1059", "Command Execution", "Execution"),
        "severity": "MEDIUM",
        "reason": [
            "New process created",
            "Could indicate malicious execution"
        ],
        "next": [
            "Review process name and command line",
            "Check parent process",
            "Validate binary reputation",
            "Look for persistence indicators"
        ]
    },

    "4697": {
        "name": "Service Installed",
        "mitre": ("T1543", "Create or Modify Service", "Persistence"),
        "severity": "HIGH",
        "reason": [
            "New service installed",
            "Possible persistence mechanism"
        ],
        "next": [
            "Identify service name and path",
            "Validate service legitimacy",
            "Check creator account",
            "Scan associated binaries"
        ]
    },

    "4720": {
        "name": "User Account Created",
        "mitre": ("T1136", "Create Account", "Persistence"),
        "severity": "HIGH",
        "reason": [
            "New user account created",
            "Potential backdoor account"
        ],
        "next": [
            "Verify account creator",
            "Check group memberships",
            "Confirm business justification",
            "Disable account if suspicious"
        ]
    },

    "4732": {
        "name": "User Added to Privileged Group",
        "mitre": ("T1098", "Account Manipulation", "Persistence"),
        "severity": "CRITICAL",
        "reason": [
            "User added to admin group",
            "High-impact privilege escalation"
        ],
        "next": [
            "Identify added user and group",
            "Verify approval",
            "Check subsequent actions",
            "Revoke access if unauthorized"
        ]
    },

    "4769": {
        "name": "Kerberos Service Ticket Requested",
        "mitre": ("T1558", "Kerberoasting", "Credential Access"),
        "severity": "HIGH",
        "reason": [
            "Suspicious Kerberos ticket requests",
            "Possible credential extraction attempt"
        ],
        "next": [
            "Identify requesting account",
            "Check service account exposure",
            "Monitor ticket request volume",
            "Reset compromised credentials"
        ]
    },

    "4740": {
        "name": "Account Locked Out",
        "mitre": ("T1110", "Brute Force", "Credential Access"),
        "severity": "MEDIUM",
        "reason": [
            "Account lockout detected",
            "Likely password attack"
        ],
        "next": [
            "Identify lockout source",
            "Check related failed logons",
            "Notify user",
            "Reset password if required"
        ]
    }
}

# ----------------------------
# Command Handling
# ----------------------------
if event not in EVENTS:
    print("Unknown Event ID. Please investigate manually.")
    exit()

data = EVENTS[event]

if args.command == "explain":
    print(f"Event ID {event}: {data['name']}")

elif args.command == "mitre":
    tid, technique, tactic = data["mitre"]
    print("MITRE ATT&CK Mapping")
    print(f"Technique: {technique}")
    print(f"ATT&CK ID: {tid}")
    print(f"Tactic: {tactic}")

elif args.command == "severity":
    print("Severity Assessment")
    print(f"Severity: {data['severity']}")
    print("Reason:")
    for r in data["reason"]:
        print(f"- {r}")

elif args.command == "next":
    print("Recommended Investigation Steps")
    for step in data["next"]:
        print(f"- {step}")