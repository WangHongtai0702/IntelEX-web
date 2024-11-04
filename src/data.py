TACTIC_TECHNIQUES_MAPPING = {
    "Reconnaissance": [
        "Active Scanning",
        "Gather Victim Host Information",
        "Gather Victim Identity Information",
        "Gather Victim Network Information",
        "Gather Victim Org Information",
        "Phishing for Information",
        "Search Closed Sources",
        "Search Open Technical Databases",
        "Search Open Websites/Domains",
        "Search Victim-Owned Websites"
    ],
    "Resource Development": [
        "Acquire Access",
        "Acquire Infrastructure",
        "Compromise Accounts",
        "Compromise Infrastructure",
        "Develop Capabilities",
        "Establish Accounts",
        "Obtain Capabilities",
        "Stage Capabilities"
    ],
    "Initial Access": [
        "Content Injection",
        "Drive-by Compromise",
        "Exploit Public-Facing Application",
        "External Remote Services",
        "Hardware Additions",
        "Phishing",
        "Replication Through Removable Media",
        "Supply Chain Compromise",
        "Trusted Relationship",
        "Valid Accounts"
    ],
    "Execution": [
        "Cloud Administration Command",
        "Command and Scripting Interpreter",
        "Container Administration Command",
        "Deploy Container",
        "Exploitation for Client Execution",
        "Inter-Process Communication",
        "Native API",
        "Scheduled Task/Job",
        "Serverless Execution",
        "Shared Modules",
        "Software Deployment Tools",
        "System Services",
        "User Execution",
        "Windows Management Instrumentation"
    ],
    "Persistence": [
        "Account Manipulation",
        "BITS Jobs",
        "Boot or Logon Autostart Execution",
        "Boot or Logon Initialization Scripts",
        "Browser Extensions",
        "Compromise Host Software Binary",
        "Create Account",
        "Create or Modify System Process",
        "Event Triggered Execution",
        "External Remote Services",
        "Hijack Execution Flow",
        "Implant Internal Image",
        "Modify Authentication Process",
        "Office Application Startup",
        "Power Settings",
        "Pre-OS Boot",
        "Scheduled Task/Job",
        "Server Software Component",
        "Traffic Signaling",
        "Valid Accounts"
    ],
    "Privilege Escalation": [
        "Abuse Elevation Control Mechanism",
        "Access Token Manipulation",
        "Account Manipulation",
        "Boot or Logon Autostart Execution",
        "Boot or Logon Initialization Scripts",
        "Create or Modify System Process",
        "Domain or Tenant Policy Modification",
        "Escape to Host",
        "Event Triggered Execution",
        "Exploitation for Privilege Escalation",
        "Hijack Execution Flow",
        "Process Injection",
        "Scheduled Task/Job",
        "Valid Accounts"
    ],
    "Defense Evasion": [
        "Abuse Elevation Control Mechanism",
        "Access Token Manipulation",
        "BITS Jobs",
        "Build Image on Host",
        "Debugger Evasion",
        "Deobfuscate/Decode Files or Information",
        "Deploy Container",
        "Direct Volume Access",
        "Domain or Tenant Policy Modification",
        "Execution Guardrails",
        "Exploitation for Defense Evasion",
        "File and Directory Permissions Modification",
        "Hide Artifacts",
        "Hijack Execution Flow",
        "Impair Defenses",
        "Impersonation",
        "Indicator Removal",
        "Indirect Command Execution",
        "Masquerading",
        "Modify Authentication Process",
        "Modify Cloud Compute Infrastructure",
        "Modify Registry",
        "Modify System Image",
        "Network Boundary Bridging",
        "Obfuscated Files or Information",
        "Plist File Modification",
        "Pre-OS Boot",
        "Process Injection",
        "Reflective Code Loading",
        "Rogue Domain Controller",
        "Rootkit",
        "Subvert Trust Controls",
        "System Binary Proxy Execution",
        "System Script Proxy Execution",
        "Template Injection",
        "Traffic Signaling",
        "Trusted Developer Utilities Proxy Execution",
        "Unused/Unsupported Cloud Regions",
        "Use Alternate Authentication Material",
        "Valid Accounts",
        "Virtualization/Sandbox Evasion",
        "Weaken Encryption",
        "XSL Script Processing"
    ],
    "Credential Access": [
        "Adversary-in-the-Middle",
        "Brute Force",
        "Credentials from Password Stores",
        "Exploitation for Credential Access",
        "Forced Authentication",
        "Forge Web Credentials",
        "Input Capture",
        "Modify Authentication Process",
        "Multi-Factor Authentication Interception",
        "Multi-Factor Authentication Request Generation",
        "Network Sniffing",
        "OS Credential Dumping",
        "Steal Application Access Token",
        "Steal or Forge Authentication Certificates",
        "Steal or Forge Kerberos Tickets",
        "Steal Web Session Cookie",
        "Unsecured Credentials"
    ],
    "Discovery": [
        "Account Discovery",
        "Application Window Discovery",
        "Browser Information Discovery",
        "Cloud Infrastructure Discovery",
        "Cloud Service Dashboard",
        "Cloud Service Discovery",
        "Cloud Storage Object Discovery",
        "Container and Resource Discovery",
        "Debugger Evasion",
        "Device Driver Discovery",
        "Domain Trust Discovery",
        "File and Directory Discovery",
        "Group Policy Discovery",
        "Log Enumeration",
        "Network Service Discovery",
        "Network Share Discovery",
        "Network Sniffing",
        "Password Policy Discovery",
        "Peripheral Device Discovery",
        "Permission Groups Discovery",
        "Process Discovery",
        "Query Registry",
        "Remote System Discovery",
        "Software Discovery",
        "System Information Discovery",
        "System Location Discovery",
        "System Network Configuration Discovery",
        "System Network Connections Discovery",
        "System Owner/User Discovery",
        "System Service Discovery",
        "System Time Discovery",
        "Virtualization/Sandbox Evasion"
    ],
    "Lateral Movement": [
        "Exploitation of Remote Services",
        "Internal Spearphishing",
        "Lateral Tool Transfer",
        "Remote Service Session Hijacking",
        "Remote Services",
        "Replication Through Removable Media",
        "Software Deployment Tools",
        "Taint Shared Content",
        "Use Alternate Authentication Material"
    ],
    "Collection": [
        "Adversary-in-the-Middle",
        "Archive Collected Data",
        "Audio Capture",
        "Automated Collection",
        "Browser Session Hijacking",
        "Clipboard Data",
        "Data from Cloud Storage",
        "Data from Configuration Repository",
        "Data from Information Repositories",
        "Data from Local System",
        "Data from Network Shared Drive",
        "Data from Removable Media",
        "Data Staged",
        "Email Collection",
        "Input Capture",
        "Screen Capture",
        "Video Capture"
    ],
    "Command and Control": [
        "Application Layer Protocol",
        "Communication Through Removable Media",
        "Content Injection",
        "Data Encoding",
        "Data Obfuscation",
        "Dynamic Resolution",
        "Encrypted Channel",
        "Fallback Channels",
        "Hide Infrastructure",
        "Ingress Tool Transfer",
        "Multi-Stage Channels",
        "Non-Application Layer Protocol",
        "Non-Standard Port",
        "Protocol Tunneling",
        "Proxy",
        "Remote Access Software",
        "Traffic Signaling",
        "Web Service"
    ],
    "Exfiltration": [
        "Automated Exfiltration",
        "Data Transfer Size Limits",
        "Exfiltration Over Alternative Protocol",
        "Exfiltration Over C2 Channel",
        "Exfiltration Over Other Network Medium",
        "Exfiltration Over Physical Medium",
        "Exfiltration Over Web Service",
        "Scheduled Transfer",
        "Transfer Data to Cloud Account"
    ],
    "Impact": [
        "Account Access Removal",
        "Data Destruction",
        "Data Encrypted for Impact",
        "Data Manipulation",
        "Defacement",
        "Disk Wipe",
        "Endpoint Denial of Service",
        "Financial Theft",
        "Firmware Corruption",
        "Inhibit System Recovery",
        "Network Denial of Service",
        "Resource Hijacking",
        "Service Stop",
        "System Shutdown/Reboot"
    ]
}

TACTIC_DESCRIPTION = {
    "Reconnaissance": "The adversary is trying to gather information they can use to plan future operations.",
    "Resource Development": "The adversary is trying to establish resources they can use to support operations.",
    "Initial Access": "The adversary is trying to get into your network.",
    "Execution": "The adversary is trying to run malicious code.",
    "Persistence": "The adversary is trying to maintain their foothold.",
    "Privilege Escalation": "The adversary is trying to gain higher-level permissions.",
    "Defense Evasion": "The adversary is trying to avoid being detected.",
    "Credential Access": "The adversary is trying to steal account names and passwords.",
    "Discovery": "The adversary is trying to figure out your environment.",
    "Lateral Movement": "The adversary is trying to move through your environment.",
    "Collection": "The adversary is trying to gather data of interest to their goal.",
    "Command and Control": "The adversary is trying to communicate with compromised systems to control them.",
    "Exfiltration": "The adversary is trying to steal data.",
    "Impact": "The adversary is trying to manipulate, interrupt, or destroy your systems and data."
}

MOTIVATING_EXAMPLE = f'''
The Initial Compromise represents the methods intruders use to first penetrate a target organization’s network. As with most other APT groups, spear phishing is APT1’s most commonly used technique. The spear phishing emails contain either a malicious attachment or a hyperlink to a malicious file. The subject line and the text in the email body are usually relevant to the recipient. APT1 also creates webmail accounts using real peoples’ names — names that are familiar to the recipient, such as a colleague, a company executive, an IT department employee, or company counsel — and uses these accounts to send the emails. As a real-world example, this is an email that APT1 sent to Mandiant employees:

Date: Wed, 18 Apr 2012 06:31:41 -0700
From: Kevin Mandia <kevin.mandia@rocketmail.com>
Subject: Internal Discussion on the Press
Release
Hello,
Shall we schedule a time to meet next week?
We need to finalize the press release.
Details click here.
Kevin Mandia

At first glance, the email appeared to be from Mandiant’s CEO, Kevin Mandia. However, further scrutiny shows that the email was not sent from a Mandiant email account, but from “kevin.mandia@rocketmail.com”. Rocketmail is a free webmail service. The account “kevin.mandia@rocketmail.com” does not belong to Mr. Mandia. Rather, an APT1 actor likely signed up for the account specifically for this spear phishing event. If anyone had clicked on the link that day (which no one did, thankfully), their computer would have downloaded a malicious ZIP file named “Internal_ Discussion_Press_Release_In_Next_Week8.zip”. This file contained a malicious executable that installs a custom APT1 backdoor that we call WEBC2-TABLE.

Although the files that APT1 actors attach or link to spear phishing emails are not always in ZIP format, this is the predominant trend we have observed in the last several years. Below is a sampling of file names that APT1 has used with their malicious ZIP files:
2012ChinaUSAviationSymposium.zip
Employee-Benefit-and-Overhead-Adjustment-Keys.zip
MARKET-COMMENT-Europe-Ends-Sharply-Lower-On-Data-Yields-Jump.zip
Negative_Reports_Of_Turkey.zip
New_Technology_For_FPGA_And_Its_Developing_Trend.zip
North_Korean_launch.zip
Oil-Field-Services-Analysis-And-Outlook.zip
POWER_GEN_2012.zip
Proactive_Investors_One2One_Energy_Investor_Forum.zip
Social-Security-Reform.zip
South_China_Sea_Security_Assessment_Report.zip
Telephonics_Supplier_Manual_v3.zip
The_Latest_Syria_Security_Assessment_Report.zip
Updated_Office_Contact_v1.zip
Updated_Office_Contact_v2.zip
Welfare_Reform_and_Benefits_Development_Plan.zip

The example file names include military, economic, and diplomatic themes, suggesting the wide range of industries that APT1 targets. Some names are also generic (e.g., “updated_office_contact_v1.zip”) and could be used for targets in any industry.

On some occasions, unsuspecting email recipients have replied to the spear phishing messages, believing they were communicating with their acquaintances. In one case a person replied, “I’m not sure if this is legit, so I didn’t open it.” Within 20 minutes, someone in APT1 responded with a terse email back: “It’s legit.” 
'''


TACTICS = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact"
]