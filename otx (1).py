"""
=============================================================================
FILE        : otx.py
AUTHOR      : Cybersecurity Analyst (Student)
DATE        : 2026-05-16
DESCRIPTION : Applied Cyber Threat Intelligence (CTI) script that interacts
              with AlienVault's Open Threat Exchange (OTX) API to:
                - Collect subscribed threat pulse data (IOCs, TTPs)
                - Parse and validate the raw API response
                - Contextualize and prioritize threats (HIGH/MEDIUM/LOW)
                - Export a structured intelligence report to a .txt file

ALGORITHM   :
  1. PROBLEM   : Collect, parse, prioritize, and report OTX threat intelligence
  2. PSEUDOCODE:
       fetch_threat_intelligence()
           → GET OTX subscribed pulses endpoint with API key header
           → Return parsed JSON on success, None on failure

       parse_threat_intelligence(data)
           → Validate data; exit gracefully if None/empty
           → For each pulse: extract name, tags, indicators, indicator count
           → Assign priority: HIGH (ransomware/phishing/APT/malware)
                              MEDIUM (trojan/botnet/backdoor/exploit/spam)
                              LOW (everything else)
           → Print summary to console
           → Write full report to otx_intelligence_report.txt

       __main__
           → Call fetch → pass result to parse

  3. CODE      : (this file)
  4. EXECUTE   : python otx.py
  5. DEBUG     : Handles HTTP errors, empty data, and missing fields gracefully
  6. DOCUMENT  : Inline comments throughout; docstrings on every function

REFERENCES  :
  - AlienVault OTX API docs: https://otx.alienvault.com/api
  - URLHaus CTI example from course PDF (Applied Cyber Threat Intelligence)
=============================================================================
"""

import requests  # For making HTTP requests to the OTX API
import json      # For pretty-printing JSON during debug (optional use)


# ---------------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------------

# OTX API endpoint – returns pulses the analyst is subscribed to
OTX_API_URL = 'https://otx.alienvault.com/api/v1/pulses/subscribed'

# Replace with your actual OTX API key; keep this confidential
OTX_API_KEY = '8235d3a78b3fcc953fe374aa30dbfa6e14d878023020862100bcac0809364669'

# Output report file name (required by CodeGrade)
REPORT_FILE = 'otx_intelligence_report.txt'

# Priority tag lists (case-insensitive matching)
# HIGH: threats with immediate, severe impact – data loss, system compromise, nation-state
HIGH_PRIORITY_TAGS = [
    'ransomware', 'phishing', 'apt', 'malware',
    'infostealer', 'stealer', 'credential harvesting', 'credential theft',
    'nation-state', 'espionage', 'remote code execution', 'rce',
    'authentication bypass', 'cryptocurrency theft', 'session hijacking',
    'discord token theft', 'telegram exfiltration'
]

# MEDIUM: threats that enable or support attacks – botnets, C2, obfuscation tools
MEDIUM_PRIORITY_TAGS = [
    'trojan', 'botnet', 'backdoor', 'exploit', 'spam',
    'c2 infrastructure', 'peer-to-peer botnet', 'webshells',
    'obfuscation techniques', 'cryptocurrency mining', 'clickfix',
    'guloader', 'agent tesla', 'lokibot', 'quasar rat'
]


# ---------------------------------------------------------------------------
# STEP 1: COLLECT THREAT DATA
# ---------------------------------------------------------------------------

def fetch_threat_intelligence():
    """
    Fetches subscribed threat intelligence pulses from the AlienVault OTX API.

    CTI Process Stage: Collection of Threat Data
        - Connects to an external threat intelligence feed (OTX)
        - Retrieves structured pulse data containing IOCs and TTPs

    Returns:
        dict : Parsed JSON response from OTX API if successful.
        None : If the request fails or a non-200 status code is returned.
    """
    # Set request headers including the OTX API key for authentication
    headers = {
        'X-OTX-API-KEY': OTX_API_KEY
    }

    try:
        # Send a GET request to the OTX subscribed pulses endpoint
        response = requests.get(OTX_API_URL, headers=headers)

        # Check if the request was successful (HTTP 200 OK)
        if response.status_code == 200:
            return response.json()  # Return the parsed JSON payload
        else:
            # Inform the analyst of the HTTP error code
            print(f"Error: Received status code {response.status_code}")
            return None

    except Exception as e:
        # Catch any network/connection errors and report them
        print(f"An error occurred: {e}")
        return None


# ---------------------------------------------------------------------------
# STEP 2 & 3: ANALYZE, PROCESS, CONTEXTUALIZE, AND PRIORITIZE THREATS
# STEP 4    : INTEGRATE WITH SECURITY OPERATIONS (export to file)
# ---------------------------------------------------------------------------

def parse_threat_intelligence(data):
    """
    Parses, prioritizes, and exports threat intelligence from OTX pulse data.

    CTI Process Stages Covered:
        - Analysis & Processing       : Extracts pulse name, tags, indicators
        - Contextualization           : Evaluates threat relevance via tags
        - Prioritization              : Labels each pulse HIGH / MEDIUM / LOW
        - Integration with Sec. Ops   : Exports structured report to .txt file

    Args:
        data (dict): The raw JSON response returned by fetch_threat_intelligence().

    Returns:
        None
    """
    # ------------------------------------------------------------------
    # VALIDATE: Exit gracefully if data is None or results list is absent
    # ------------------------------------------------------------------
    if not data or not data.get('results'):
        print("No usable threat intelligence data returned. Exiting gracefully.")
        return

    # Retrieve the list of pulse objects from the API response
    pulses = data.get('results', [])

    # Inform the analyst how many pulses were retrieved
    print(f"\n{'='*60}")
    print(f"  OTX Threat Intelligence Report")
    print(f"  Total Pulses Retrieved: {len(pulses)}")
    print(f"{'='*60}\n")

    # ------------------------------------------------------------------
    # OPEN REPORT FILE for writing (Step 4: Integration/Export)
    # ------------------------------------------------------------------
    with open(REPORT_FILE, 'w') as report:

        # Write report header
        report.write("=" * 60 + "\n")
        report.write("  OTX THREAT INTELLIGENCE REPORT\n")
        report.write(f"  Total Pulses Retrieved: {len(pulses)}\n")
        report.write("=" * 60 + "\n\n")

        # --------------------------------------------------------------
        # LOOP: Process each pulse (one pulse = one threat campaign/IOC set)
        # --------------------------------------------------------------
        for index, pulse in enumerate(pulses, start=1):

            # ----------------------------------------------------------
            # EXTRACT key fields from the pulse object
            # ----------------------------------------------------------
            name        = pulse.get('name', 'N/A')          # Pulse/campaign name
            tags        = pulse.get('tags', [])              # Associated threat tags
            indicators  = pulse.get('indicators', [])        # List of IOC objects
            description = pulse.get('description', '').strip() or 'No description provided.'

            # Count total number of indicators (IOCs) in this pulse
            indicator_count = len(indicators)

            # ----------------------------------------------------------
            # PRIORITIZE: Assign threat level based on tag keywords
            # Priority logic mirrors the URLHaus example from the PDF
            # but extends it with a MEDIUM tier for broader coverage
            # ----------------------------------------------------------

            # Normalize tags to lowercase for case-insensitive comparison
            tags_lower = [tag.lower() for tag in tags]

            if any(tag in tags_lower for tag in HIGH_PRIORITY_TAGS):
                priority = "HIGH"
            elif any(tag in tags_lower for tag in MEDIUM_PRIORITY_TAGS):
                priority = "MEDIUM"
            else:
                priority = "LOW"

            # ----------------------------------------------------------
            # DISPLAY: Print pulse summary to the console
            # ----------------------------------------------------------
            print(f"Pulse #{index}")
            print(f"  Name            : {name}")
            print(f"  Priority        : {priority}")
            print(f"  Tags            : {', '.join(tags) if tags else 'None'}")
            print(f"  Indicator Count : {indicator_count}")
            print(f"  Description     : {description[:120]}...")  # Truncate for readability
            print()

            # ----------------------------------------------------------
            # EXPORT: Write full pulse details to the report file
            # ----------------------------------------------------------
            report.write(f"Pulse #{index}\n")
            report.write(f"  Name            : {name}\n")
            report.write(f"  Priority        : {priority}\n")
            report.write(f"  Tags            : {', '.join(tags) if tags else 'None'}\n")
            report.write(f"  Indicator Count : {indicator_count}\n")
            report.write(f"  Description     : {description}\n")

            # Write individual indicators (IOCs) to the report
            if indicators:
                report.write(f"  Indicators (IOCs):\n")
                for ioc in indicators:
                    ioc_type      = ioc.get('type', 'N/A')   # e.g., domain, IP, URL, hash
                    ioc_indicator = ioc.get('indicator', 'N/A')  # The actual IOC value
                    report.write(f"    - [{ioc_type}] {ioc_indicator}\n")
            else:
                report.write(f"  Indicators (IOCs): None\n")

            # Separator between pulses in the report
            report.write("\n" + "-" * 60 + "\n\n")

    # ------------------------------------------------------------------
    # CONFIRM: Notify the analyst that the report has been written
    # ------------------------------------------------------------------
    print(f"[+] Intelligence report successfully exported to: {REPORT_FILE}")
    print(f"[+] Review '{REPORT_FILE}' for full IOC listings and pulse details.\n")


# ---------------------------------------------------------------------------
# MAIN BLOCK – Entry point for the CTI script
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    """
    Execution flow:
      1. fetch_threat_intelligence() → pulls raw pulse data from OTX API
      2. parse_threat_intelligence() → validates, analyzes, prioritizes, exports
    """

    print("\n[*] Starting OTX Cyber Threat Intelligence Collection...\n")

    # Step 1: Fetch raw threat intelligence from OTX
    threat_data = fetch_threat_intelligence()

    # Step 2–4: Parse, prioritize, and export the intelligence
    parse_threat_intelligence(threat_data)

    print("[*] CTI process complete.\n")
