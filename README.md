# Purview Audit Log Parser

A Python-based parser for Microsoft Purview Audit Log exports, built to support Microsoft 365 incident response and digital forensic investigations.

The tool automatically parses the complex JSON contained within the Purview AuditData field and transforms it into investigation-focused Excel worksheets, reducing manual data preparation and enabling analysts to spend more time investigating and less time cleaning data.

## Features

### Exchange Investigation

- Exchange investigation worksheet
- MailItemsAccessed (Bind) parsing
- MailItemsAccessed (Sync) parsing
- Multi-message subject extraction
- Multi-message Internet Message ID extraction

### Inbox Rule Analysis

- New-InboxRule
- Set-InboxRule
- Enable-InboxRule
- Disable-InboxRule
- Remove-InboxRule
- UpdateInboxRules

### SharePoint / OneDrive Investigation

- File access activity
- File download activity
- Sharing activity
- User and device information

### Azure AD Investigation

- UserLoggedIn
- UserLoggedInFailed
- Sign-in metadata
- Device information

### IP Address Analysis

- IP normalisation
- IP source identification
- Deduplicated IP analysis worksheet

### General Features

- Workload identification
- Investigation-focused worksheets
- Parser statistics
- Workload summary
- Parser error reporting

---

## Output Worksheets

The parser generates the following worksheets:

- Parser Statistics
- Workload Summary
- IP-Analysis
- All Events
- Parser Errors
- Exchange-Investigation
- InboxRules
- MailItemsAccessed-Bind
- MailItemsAccessed-Sync
- SPOD-Investigation
- AzureAD-Investigation
- Teams

---

## Installation

Clone the repository:

```bash
git clone https://github.com/rukmandfir/Purview-Audit-Log-Parser.git
```

Install requirements:

```bash
pip install -r requirements.txt
```

---

## Usage

Place the Purview audit log CSV export into the input folder and run:

```bash
python main.py
```

The parsed workbook will be created in the output folder.

---

## Typical Use Cases

- Business Email Compromise (BEC) investigations
- Microsoft 365 incident response
- Insider threat investigations
- Microsoft Purview audit log review
- eDiscovery support
- Rapid investigation triage
- Timeline development

---

## Roadmap

### Planned Features

- IP geolocation enrichment
- Investigation timeline worksheet
- BEC summary worksheet
- Suspicious activity worksheet
- Teams investigation worksheet
- Additional Microsoft 365 workload support

---

## Disclaimer

This project is intended to assist investigators by reducing manual data preparation effort. Results should always be validated and reviewed by the investigator.

Do not upload real client data to public repositories.

---

## License

This project is licensed under the MIT License.
