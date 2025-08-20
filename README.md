# IocScraper
A simple Python script that automatically extracts Indicators of Compromise (IOCs) from cybersecurity threat reports, with boundary detection and validation. Instead of manually copying IOCs from technical reports when you find something valuable, this tool automates the process and creates a detailed summary.

## Features
- Multiple IOC Types: Extracts IPs, domains, URLs, emails, and file hashes (MD5/SHA1/SHA256).
- Multiple validation mechanisms and fetches up-to-date TLDs from IANA.
- Defanged IOC Support: Handles obfuscated IOCs (hxxp, [.], etc) commonly found in reports.
- False positive filtering: Configure filtering for private IPs, common domains and file extensions in `data/false_positive.json`.

## File structure
```
.
├── data
│   ├── false_positives.json
│   └── tld_cache.json
├── README.md
├── requirements.txt
├── src
│   ├── __init__.py
│   └── main.py
└── utils
    ├── datautils.py
    ├── fileutils.py
    ├── __init__.py
    ├── logger.py
    └── networkutils.py

```

## Requirements
- Python >= 3.10.
- External dependencies as listed in `requirements.txt`.

## Installation
```bash
pip install -r requirements.txt

# Ensure Chrome is installed for Selenium fallback
```

## Usage
Extract IOCs from a threat report:
```bash
python3 -m src.main -u "https://example.com/threat-report"
```
Use custom false positives configuration:
```bash
python3 -m src.main -u "https://example.com/report" -f false_positives.json -o output/
```

## Note
False positives may occur because we extract IOCs using general regex patterns that can match unintended content. 

If IOCs appear near other data fields within the main document text (rather than in dedicated appendices or similar sections), the extractor may inadvertently capture those fields as IOCs. So keep this in mind and validate each run.
```python3
MAX_LINES_WITHOUT_IOCS = 100

for ioc_type, values in iocs.items():
    mapped_type = key_map.get(ioc_type, ioc_type)
    if mapped_type not in all_iocs:
        continue

    new_values = values - all_iocs[mapped_type]
    if new_values:
        all_iocs[mapped_type].update(new_values)
        new_found = True
        total_iocs_found += len(new_values)

if new_found:
    lines_since_last_ioc = 0
else:
    lines_since_last_ioc += 1

if lines_since_last_ioc >= MAX_LINES_WITHOUT_IOCS:
    if total_iocs_found > 0:
        self.logger.info(
            f"No new IOCs found in {lines_since_last_ioc} consecutive lines, stopping"
        )
    else:
        self.logger.info(f"Last processed line: {line}")
        break
```

This tool is also frequently used with my other tool https://github.com/olofmagn/iocqueryx. I might build some automation between these tools in the future.

## Output
- Individual `.txt` files for each IOC type (IPs, domains, URLs, emails, hashes).
- A comprehensive JSON summary with extraction metadata.
- Organized files with timestamps for easy tracking.

Example run:
```json
{
  "source_url": "https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities/",
  "timestamp": "2025-08-20T18:47:49.648998",
  "total_iocs": 43,
  "ioc_counts": {
    "hashes": 19,
    "filenames": 14,
    "ips": 5,
    "domains": 5,
    "urls": 0,
    "emails": 0
  },
  "combined_iocs": {
    "hashes": [
      "1eb914c09c873f0a7bcf81475ab0f6bdfaccc6b63bf7e5f2dbf19295106af192",
      "24480dbe306597da1ba393b6e30d542673066f98826cc07ac4b9033137f37dbf",
      "445a37279d3a229ed18513e85f0c8d861c6f560e0f914a5869df14a74b679b86",
      "4c1750a14915bf2c0b093c2cb59063912dfa039a2adfe6d26d6914804e2ae928",
      "567cb8e8c8bd0d909870c656b292b57bcb24eb55a8582b884e0a228e298e7443",
      "62881359e75c9e8899c4bc9f452ef9743e68ce467f8b3e4398bebacde9550dea",
      "6753b840cec65dfba0d7d326ec768bff2495784c60db6a139f51c5e83349ac4d",
      "6b273c2179518dacb1218201fd37ee2492a5e1713be907e69bf7ea56ceca53a5",
      "6f6db63ece791c6dc1054f1e1231b5bbcf6c051a49bad0784569271753e24619",
      "7ae971e40528d364fa52f3bb5e0660ac25ef63e082e3bbd54f153e27b31eae68",
      "83705c75731e1d590b08f9357bc3b0f04741e92a033618736387512b40dab060",
      "92bb4ddb98eeaf11fc15bb32e71d0a63256a0ed826a03ba293ce3a8bf057a514",
      "b180ab0a5845ed619939154f67526d2b04d28713fcc1904fbd666275538f431d",
      "b5a78616f709859a0d9f830d28ff2f9dbbb2387df1753739407917e96dadf6b0",
      "c27b725ff66fdfb11dd6487a3815d1d1eba89d61b0e919e4d06ed3ac6a74fe94",
      "c2c1fec7856e8d49f5d49267e69993837575dbbec99cd702c5be134a85b2c139",
      "d6da885c90a5d1fb88d0a3f0b5d9817a82d5772d5510a0773c80ca581ce2486d",
      "f54ae00a9bae73da001c4d3d690d26ddf5e8e006b5562f936df472ec5e299441",
      "ffbc9dfc284b147e07a430fe9471e66c716a84a1f18976474a54bee82605fa9a"
    ],
    "filenames": [
      "\\template\\layouts\\debug_dev.js",
      "app/file.ps1",
      "cmd.exe",
      "debug_dev.js",
      "iis_server_dll.dll",
      "iisreset.exe",
      "services.exe",
      "sharphostinfo.x64.exe",
      "spinstall.aspx",
      "spinstall0.aspx",
      "spinstall1.aspx",
      "spinstall2.aspx",
      "w3wp.exe",
      "xd.exe"
    ],
    "ip_addresses": [
      "104.238.159.149",
      "131.226.2.6",
      "134.199.202.205",
      "188.130.206.168",
      "65.38.121.198"
    ],
    "domains": [
      "asp.net",
      "c34718cbb4c6.ngrok-free.app",
      "connectednetworks.name",
      "msupdate.updatemicfosoft.com",
      "update.updatemicfosoft.com"
    ]
  }
}
```

## License
This project is open-source and licensed under the MIT License. See the LICENSE file for details.
