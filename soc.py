import argparse

parser = argparse.ArgumentParser(
    description="SOC Assistant CLI powered by GitHub Copilot"
)

parser.add_argument(
    "command",
    choices=["explain", "mitre", "next","severity"],
    help="SOC action to perform"
)

parser.add_argument(
    "input",
    help="Event ID, log snippet, or incident description"
)

args = parser.parse_args()

# ---------------- EXPLAIN ----------------
if args.command == "explain":
    print("[+] Explaining security event\n")

    if "4625" in args.input:
        print("Event ID 4625: Failed Logon Attempt\n")
        print("What it means:")
        print("- A user account failed to authenticate")
        print("- Common in brute-force or password spray attacks\n")

        print("Possible causes:")
        print("- Incorrect password")
        print("- Brute-force attack")
        print("- Password spraying")
        print("- Disabled or locked account\n")

        print("Initial SOC actions:")
        print("- Identify source IP address")
        print("- Check number of failed attempts")
        print("- Correlate with successful logons")
        print("- Validate if account is locked or disabled")
    elif "4624" in args.input:
        print("Event ID 4624: Successful Logon")
        print("Meaning:")
        print("- User successfully authenticated")
        print("SOC Note:")
        print("- Check if preceded by multiple 4625 events")
    else:
        print("Unknown event ID.")
        print("Consider manual analysis or threat intelligence lookup.")

# ---------------- MITRE ----------------
elif args.command == "mitre":
    print("[+] MITRE ATT&CK Mapping\n")

    if "4625" in args.input:
        print("Event ID: 4625")
        print("Technique: Brute Force")
        print("MITRE ATT&CK ID: T1110")
        print("Tactics: Credential Access")

    else:
        print("No MITRE mapping available for this input.")

# ---------------- NEXT STEPS ----------------
elif args.command == "next":
    print("[+] Recommended Investigation Steps\n")

    if "4625" in args.input:
        print("1. Identify source IP and geolocation")
        print("2. Check for multiple accounts from same IP")
        print("3. Review account lockout events")
        print("4. Search for successful logons after failures")
        print("5. Check for lateral movement indicators")
        print("6. Escalate if pattern suggests attack")

    else:
        print("Define investigation steps manually.")
    # ---------------- SEVERITY ----------------
elif args.command == "severity":
    print("[+] Severity Assessment\n")

    if "4625" in args.input:
        print("Event ID: 4625")
        print("Severity: HIGH")
        print("Reason:")
        print("- Repeated authentication failures")
        print("- Possible brute-force or password spray attack")
        print("- High risk to account security")

    else:
        print("Severity: LOW")
        print("Reason: Unknown or isolated event")    
