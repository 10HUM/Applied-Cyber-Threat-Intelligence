# Cyber Threat Intelligence (CTI) Automation Script

A Python project focused on leveraging the Cyber Threat Intelligence (CTI) lifecycle to collect, analyze, contextualize, and integrate threat data using the AlienVault Open Threat Exchange (OTX) API.

## 📋 Scenario
As a cybersecurity analyst, this script helps gather threat intelligence from AlienVault OTX to identify Indicators of Compromise (IOCs), assess potential risks, and prepare intelligence feeds for security operations integration.

## 🛠️ Features & Implementation Steps
- **Step 1: Data Collection (`fetch_threat_intelligence`)**: Connects to the AlienVault OTX API to fetch recent pulses and threat indicators.
- **Step 2: Data Analysis & Processing (`parse_threat_intelligence`)**: Parses incoming JSON responses to extract actionable IOCs (e.g., IPs, domains, file hashes).
- **Step 3: Contextualization & Prioritization**: Evaluates indicators against organizational risk levels.
- **Step 4: Integration**: Structures threat data for potential ingestion into SIEM or security operations workflows.

## 🚀 Getting Started

### Prerequisites
- Python 3.8+
- An AlienVault OTX account and API Key ([Sign up here](https://otx.alienvault.com/))
- Required Python libraries (`requests`, etc.)

### Installation & Setup
1. Clone the repository:
   ```bash
   git clone [https://github.com/your-username/your-repo-name.git](https://github.com/your-username/your-repo-name.git)
   cd your-repo-name
