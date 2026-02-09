import argparse

parser = argparse.ArgumentParser(
    description="SOC Assistant CLI powered by GitHub Copilot"
)

parser.add_argument(
    "command",
    choices=["explain", "mitre", "next", "severity"],
    help="SOC action to perform"
)

parser.add_argument(
    "input",
    help="Event ID or incident description"
)

args = parser.parse_args()

# ---------------- EXPLAIN ----------------
if args.command == "explain":
    print("\n[+] Event Explanation\n")

    if "4625" in args.input:
        print("Event ID 4625 – Failed Logon")
        print("- Incorrect credentials")
        print("- Brute-force or password spray attempt")

    elif "4624" in args.input:
        print("Event ID 4624 – Successful Logon")
        print("- User successfully authenticated")
        print("- Validate logon type and source")

    elif "4688" in args.input:
        print("Event ID 4688 – Process Creation")
        print("- A new process was executed")
        print("- Common malware execution indicator")

    elif "4672" in args.input:
        print("Event ID 4672 – Privileged Logon")
        print("- Admin-level privileges assigned")
        print("- High-risk if unexpected")

    elif "4720" in args.input:
        print("Event ID 4720 – User Account Created")
        print("- New account added to the system")

    elif "4726" in args.input:
        print("Event ID 4726 – User Account Deleted")
        print("- Account removal detected")

    elif "4732" in args.input:
        print("Event ID 4732 – Added to Privileged Group")
        print("- User added to admin group")

    elif "4740" in args.input:
        print("Event ID 4740 – Account Locked Out")
        print("- Excessive authentication failures")

    elif "4769" in args.input:
        print("Event ID 4769 – Kerberos Ticket Requested")
        print("- Can indicate Kerberoasting")

    elif "1102" in args.input:
        print("Event ID 1102 – Security Log Cleared")
        print("- Strong attacker activity indicator")

    else:
        print("Unknown event – manual investigation required")

# ---------------- MITRE ----------------
elif args.command == "mitre":
    print("\n[+] MITRE ATT&CK Mapping\n")

    mappings = {
        "4625": ("Brute Force", "T1110", "Credential Access"),
        "4624": ("Valid Accounts", "T1078", "Defense Evasion"),
        "4688": ("Command Execution", "T1059", "Execution"),
        "4672": ("Privilege Escalation", "T1068", "Privilege Escalation"),
        "4720": ("Account Manipulation", "T1136", "Persistence"),
        "4726": ("Defense Evasion", "T1070", "Defense Evasion"),
        "4732": ("Account Manipulation", "T1098", "Persistence"),
        "4740": ("Brute Force", "T1110", "Credential Access"),
        "4769": ("Kerberoasting", "T1558", "Credential Access"),
        "1102": ("Indicator Removal", "T1070", "Defense Evasion")
    }

    for key in mappings:
        if key in args.input:
            technique, tid, tactic = mappings[key]
            print(f"Technique: {technique}")
            print(f"ATT&CK ID: {tid}")
            print(f"Tactic: {tactic}")
            break
    else:
        print("No MITRE mapping available")

# ---------------- NEXT STEPS ----------------
elif args.command == "next":
    print("\n[+] Recommended Investigation Steps\n")

    print("- Identify source host and IP")
    print("- Correlate with adjacent security events")
    print("- Validate user and asset criticality")
    print("- Check for lateral movement")
    print("- Escalate if attacker behavior suspected")

# ---------------- SEVERITY ----------------
elif args.command == "severity":
    print("\n[+] Severity Assessment\n")

    if any(x in args.input for x in ["1102", "4732", "4672"]):
        print("Severity: CRITICAL")

    elif any(x in args.input for x in ["4625", "4688", "4769"]):
        print("Severity: HIGH")

    else:
        print("Severity: MEDIUM")