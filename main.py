import json
from pathlib import Path

import pandas as pd


INPUT_FILE = Path("input/purview_audit_log_InsiderThreat.csv")
OUTPUT_FILE = Path("output/purview_parsed_InsiderThreat.xlsx")

BASE_COLUMNS = ["RecordId", "CreationDate", "RecordType", "Operation", "UserId"]

IP_FIELDS = [
    "ClientIPAddress", "ClientIP", "ClientIp", "ActorIpAddress", "ActorIPAddress",
    "IPAddress", "IP", "DeviceIPAddress", "SourceIPAddress", "SourceIP",
    "RemoteIP", "RemoteIPAddress",
]

USER_FIELDS = ["UserId", "MailboxOwnerUPN", "MailboxUserUPN", "User", "Actor", "UserKey"]
TIMESTAMP_FIELDS = ["CreationDate", "CreationTime", "TimeGenerated", "Timestamp"]

MAIL_ITEMS_ACCESSED_BIND_COLUMNS = [
    "RecordId", "CreationDate", "RecordType", "Operation", "UserId",
    "NormalisedIPAddress", "IPAddressSource", "ResultStatus", "UserKey",
    "Version", "ActorInfoString", "ClientAppId", "ClientIPAddress",
    "LogonType", "MailboxOwnerUPN", "MailAccessType", "Subject",
    "InternetMessageId",
]

MAIL_ITEMS_ACCESSED_SYNC_COLUMNS = [
    "RecordId", "CreationDate", "RecordType", "Operation", "UserId",
    "NormalisedIPAddress", "IPAddressSource", "ResultStatus", "UserType",
    "ClientIp", "ActorInfoString", "ClientIPAddress", "ClientInfoString",
    "ClientProcessName", "ClientRequestId", "HostAppId", "LogonType",
    "MailboxOwnerUPN", "MailAccessType", "FolderPath", "Name",
]

EXCHANGE_INVESTIGATION_COLUMNS = [
    "RecordId", "CreationDate", "RecordType", "Operation", "UserId",
    "OrganizationId", "ResultStatus", "UserKey", "UserType", "Version",
    "Workload", "ClientIP", "ActorInfoString", "ClientIPAddress",
    "ClientInfoString", "ClientProcessName", "ClientRequestId",
    "ClientVersion", "ExternalAccess", "LogonType", "MailboxOwnerUPN",
    "OrganizationName", "OriginatingServer", "SessionId", "AppId",
    "TokenTenantId", "ContactEmail1DisplayName",
    "ContactEmail1EmailAddress", "Subject", "InternetMessageId",
    "NormalisedIPAddress", "IPAddressSource",
]

INBOX_RULES_COLUMNS = [
    "RecordId", "CreationDate", "RecordType", "Operation", "UserId",
    "NormalisedIPAddress", "IPAddressSource", "MailboxOwnerUPN",
    "ClientIPAddress", "ActorInfoString", "ClientInfoString",
    "ExternalAccess", "LogonType", "ResultStatus", "RuleName",
    "ForwardTo", "RedirectTo", "MoveToFolder", "DeleteMessage",
    "MarkAsRead", "StopProcessingRules", "SubjectContainsWords", "From",
]

SPOD_INVESTIGATION_COLUMNS = [
    "RecordId", "CreationDate", "RecordType", "Operation", "UserId",
    "OrganizationId", "UserKey", "UserType", "Version", "Workload",
    "ClientIP", "ApplicationId", "AuthenticationType", "BrowserName",
    "BrowserVersion", "CorrelationId", "EventSource", "GeoLocation",
    "IsManagedDevice", "ListId", "ListItemUniqueId", "Platform", "Site",
    "UserAgent", "WebId", "DeviceDisplayName", "EventSignature",
    "HighPriorityMediaProcessing", "ListBaseType", "ListServerTemplate",
    "SourceRelativeUrl", "SourceFileName", "SourceFileExtension",
    "SourceFileExtention", "ApplicationDisplayName", "SiteUrl", "ObjectId",
    "FileSizeBytes", "MachineId", "Permission", "SharingLinkScope",
    "CrossScopeSyncDelete", "EventData", "UniqueSharingId",
    "DoNotDistributeEvent", "FileSyncBytesCommitted", "ImplicitShare",
    "CustomizedDoclib",
]

AZURE_AD_INVESTIGATION_COLUMNS = [
    "RecordId", "CreationDate", "RecordType", "Operation", "UserId",
    "NormalisedIPAddress", "IPAddressSource", "ResultStatus", "UserType",
    "ClientIP", "ActorInfoString", "ClientIPAddress", "ClientInfoString",
    "ClientProcessName", "LogonType", "ApplicationId", "IsManagedDevice",
    "DeviceDisplayName", "ActorIpAddress",
]

TIMELINE_COLUMNS = [
    "RecordId", "RecordType", "CreationDate", "EventTimestamp", "ParserConnector", "Workload",
    "Operation", "UserId", "PrimaryUser", "NormalisedIPAddress",
    "IPAddressSource", "SuspicionScore", "Severity",
    "SuspicionReason", "EventSummary",
]

SUSPICIOUS_ACTIVITY_COLUMNS = TIMELINE_COLUMNS

POTENTIAL_INCIDENTS_COLUMNS = [
    "PrimaryUser", "Pattern", "Severity", "ConfidenceScore", "FirstSeen", "LastSeen", "TimeWindowMinutes", "SupportingOperations", "SupportingIPs",
    "EventCount", "Reason",
]

INVESTIGATION_SUMMARY_COLUMNS = [
    "Metric", "Value",
]

def parse_audit_data(value):
    if pd.isna(value):
        return {}
    try:
        return json.loads(value)
    except Exception:
        return {}


def parse_audit_error(value):
    if pd.isna(value):
        return "AuditData is empty"
    try:
        json.loads(value)
        return ""
    except Exception as error:
        return str(error)


def get_first_value(row, fields):
    for field in fields:
        value = row.get(field)
        if pd.notna(value) and str(value).strip():
            return str(value).strip()
    return ""


def get_first_field_name(row, fields):
    for field in fields:
        value = row.get(field)
        if pd.notna(value) and str(value).strip():
            return field
    return ""


def extract_operation_property(row, property_name):
    operation_properties = row.get("OperationProperties")

    if isinstance(operation_properties, list):
        for item in operation_properties:
            if isinstance(item, dict):
                if str(item.get("Name", "")).strip().lower() == property_name.lower():
                    return item.get("Value", "")

    return ""


def extract_name_value_list(row, source_field, target_name):
    values = row.get(source_field)

    if isinstance(values, list):
        for item in values:
            if isinstance(item, dict):
                name = str(item.get("Name", "")).strip().lower()
                if name == target_name.lower():
                    return item.get("Value", "")

    return ""


def extract_rule_field(row, field_name):
    return (
        get_first_value(row, [field_name])
        or extract_operation_property(row, field_name)
        or extract_name_value_list(row, "Parameters", field_name)
        or extract_name_value_list(row, "OperationProperties", field_name)
    )


def normalise_inbox_rule_fields(df):
    rule_fields = [
        "RuleName", "ForwardTo", "RedirectTo", "MoveToFolder",
        "DeleteMessage", "MarkAsRead", "StopProcessingRules",
        "SubjectContainsWords", "From",
    ]

    output = df.copy()

    for field in rule_fields:
        output[field] = output.apply(
            lambda row: extract_rule_field(row, field),
            axis=1,
        )

    return output


def get_parent_folder_value(row, field_name):
    possible_columns = [
        f"ParentFolder.{field_name}",
        f"ParentFolder.{field_name.lower()}",
        f"ParentFolder.{field_name.upper()}",
        f"ParentFolder_{field_name}",
        f"ParentFolder_{field_name.lower()}",
        f"ParentFolder_{field_name.upper()}",
        f"Item.ParentFolder.{field_name}",
        f"Item.ParentFolder.{field_name.lower()}",
        f"Item.ParentFolder.{field_name.upper()}",
    ]

    for column in possible_columns:
        value = row.get(column)
        if pd.notna(value) and str(value).strip():
            return str(value).strip()

    parent_folder = row.get("ParentFolder")
    if isinstance(parent_folder, dict):
        for key in [field_name, field_name.lower(), field_name.upper()]:
            value = parent_folder.get(key)
            if value:
                return str(value).strip()

    item = row.get("Item")
    if isinstance(item, dict):
        parent_folder = item.get("ParentFolder")
        if isinstance(parent_folder, dict):
            for key in [field_name, field_name.lower(), field_name.upper()]:
                value = parent_folder.get(key)
                if value:
                    return str(value).strip()

    return ""


def normalise_mailitemsaccessed_sync_fields(combined):
    for column in ["FolderPath", "Name"]:
        if column not in combined.columns:
            combined[column] = ""

    combined["FolderPath"] = combined.apply(
        lambda row: row.get("FolderPath")
        if pd.notna(row.get("FolderPath")) and str(row.get("FolderPath")).strip()
        else get_parent_folder_value(row, "Path"),
        axis=1,
    )

    combined["Name"] = combined.apply(
        lambda row: row.get("Name")
        if pd.notna(row.get("Name")) and str(row.get("Name")).strip()
        else get_parent_folder_value(row, "Name"),
        axis=1,
    )

    return combined


def classify_workload(row):
    workload = get_first_value(row, ["Workload", "workload"])
    operation = get_first_value(row, ["Operation", "operation"])
    record_type = get_first_value(row, ["RecordType", "recordtype"])

    combined_text = f"{workload} {operation} {record_type}".lower()

    if "exchange" in combined_text or "mail" in combined_text or "inboxrule" in combined_text:
        return "Exchange"
    if "sharepoint" in combined_text or "onedrive" in combined_text:
        return "SharePoint-OneDrive"
    if "teams" in combined_text:
        return "Teams"
    if (
        "azureactivedirectory" in combined_text
        or "azure active directory" in combined_text
        or "userloggedin" in combined_text
    ):
        return "AzureAD"

    return "Unknown-Unparsed"


def ensure_columns(df, columns):
    output = df.copy()
    for column in columns:
        if column not in output.columns:
            output[column] = ""
    return output[columns]


def extract_email_items(row, max_items=20):
    items = []

    for field in ["AffectedItems", "Folders", "Items", "Messages", "FolderItems"]:
        value = row.get(field)

        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    items.append(item)

                    nested_items = item.get("FolderItems")
                    if isinstance(nested_items, list):
                        for nested_item in nested_items:
                            if isinstance(nested_item, dict):
                                items.append(nested_item)

    output = {}

    for index, item in enumerate(items[:max_items], start=1):
        output[f"EmailSubject_{index}"] = (
            item.get("Subject")
            or item.get("subject")
            or item.get("Name")
            or item.get("name")
            or ""
        )

        output[f"InternetMessageId_{index}"] = (
            item.get("InternetMessageId")
            or item.get("InternetMessageID")
            or item.get("internetMessageId")
            or item.get("MessageId")
            or item.get("MessageID")
            or ""
        )

    return pd.Series(output)


def add_email_item_columns(df, max_items=20):
    if df.empty:
        return df

    expanded = df.apply(
        lambda row: extract_email_items(row, max_items=max_items),
        axis=1,
    )

    return pd.concat([df, expanded], axis=1)


def get_dynamic_email_columns(df):
    return [
        column for column in df.columns
        if column.startswith("EmailSubject_")
        or column.startswith("InternetMessageId_")
    ]


def create_ip_analysis(combined):
    ip_rows = combined[
        combined["NormalisedIPAddress"].astype(str).str.strip() != ""
    ].copy()

    if ip_rows.empty:
        return pd.DataFrame(
            columns=[
                "IPAddress", "EventCount", "FirstSeen", "LastSeen",
                "IPAddressSources", "Users", "Operations",
            ]
        )

    return (
        ip_rows
        .groupby("NormalisedIPAddress")
        .agg(
            EventCount=("NormalisedIPAddress", "count"),
            FirstSeen=("CreationDate", "min"),
            LastSeen=("CreationDate", "max"),
            IPAddressSources=("IPAddressSource", lambda x: ", ".join(sorted(set(x.dropna())))),
            Users=("UserId", lambda x: ", ".join(sorted(set(x.dropna())))),
            Operations=("Operation", lambda x: ", ".join(sorted(set(x.dropna())))),
        )
        .reset_index()
        .rename(columns={"NormalisedIPAddress": "IPAddress"})
    )


def get_severity(score):
    if score >= 90:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    if score > 0:
        return "Low"
    return ""

def is_external_email(value, internal_domains=None):
    if internal_domains is None:
        internal_domains = ["contoso.com"]

    value = str(value).lower().strip()

    if not value or "@" not in value:
        return False

    return not any(value.endswith(f"@{domain}") for domain in internal_domains)

def assess_suspicion(row):
    operation = str(row.get("Operation", "")).lower()
    reasons = []
    score = 0

    high_risk_operations = {
        "new-inboxrule": 90,
        "set-inboxrule": 90,
        "updateinboxrules": 90,
        "harddelete": 80,
        "softdelete": 70,
        "anonymouslinkcreated": 80,
        "filesyncdownloadedfull": 70,
    }

    medium_risk_operations = {
        "mailitemsaccessed": 60,
        "searchqueryinitiated": 50,
        "filedownloaded": 50,
        "sharingset": 50,
        "userloggedinfailed": 30,
	"filerecycled": 70,
    }

    external_domains = [
    	"gmail.com",
    	"outlook.com",
    	"hotmail.com",
    	"yahoo.com",
    	"icloud.com",
    	"proton.me",
    	"protonmail.com",
    ]

    recipient = str(row.get("Recipient", "")).lower()

    if any(domain in recipient for domain in external_domains):
    	score = max(score, 70)
    	reasons.append("Email sent to external personal mailbox")

    for op, value in high_risk_operations.items():
        if op in operation:
            score = max(score, value)
            reasons.append(f"High-risk operation: {row.get('Operation', '')}")

    for op, value in medium_risk_operations.items():
        if op in operation:
            score = max(score, value)
            reasons.append(f"Review operation: {row.get('Operation', '')}")

    for field in ["ForwardTo", "RedirectTo"]:
        value = row.get(field)

        if pd.notna(value) and str(value).strip():
            score = max(score, 90)
            reasons.append(f"Inbox rule contains {field}")

            if is_external_email(value):
                score = max(score, 95)
                reasons.append(
                    f"Inbox rule forwards or redirects to external address: {field}"
                )

    move_to_folder = str(row.get("MoveToFolder", "")).lower()

    suspicious_folders = [
        "deleted",
        "deleted items",
        "rss",
        "rss feeds",
        "archive",
        "junk",
        "junk email",
    ]

    if any(folder in move_to_folder for folder in suspicious_folders):
        score = max(score, 80)
        reasons.append(
            f"Inbox rule moves mail to suspicious folder: {row.get('MoveToFolder')}"
        )

    for field in ["DeleteMessage", "MarkAsRead", "StopProcessingRules"]:
        value = str(row.get(field, "")).lower()
        if value in ["true", "yes", "1"]:
            score = max(score, 80)
            reasons.append(f"Inbox rule option enabled: {field}")

    sharing_scope = str(row.get("SharingLinkScope", "")).lower()
    if sharing_scope in ["anonymous", "anyone"]:
        score = max(score, 80)
        reasons.append("Anonymous or Anyone sharing link")

    external_domains = [
    	"gmail.com",
    	"outlook.com",
    	"hotmail.com",
    	"yahoo.com",
    	"icloud.com",
    	"proton.me",
    	"protonmail.com",
     ]

    recipient = str(row.get("Recipient", "")).lower()

    if any(domain in recipient for domain in external_domains):
    	score = max(score, 70)
    	reasons.append("Email sent to external personal mailbox")

    managed_device = str(row.get("IsManagedDevice", "")).lower()
    if managed_device == "false":
        score = max(score, 40)
        reasons.append("Unmanaged device")

    return pd.Series({
        "SuspicionScore": score,
        "Severity": get_severity(score),
        "SuspicionReason": "; ".join(sorted(set(reasons))) if reasons else "",
    })

def create_event_summary(row):
    operation = str(row.get("Operation", ""))
    operation_lower = operation.lower()
    user = row.get("PrimaryUser") or row.get("UserId", "")
    ip = row.get("NormalisedIPAddress", "")
    workload = row.get("Workload") or row.get("ParserConnector", "")

    if "new-inboxrule" in operation_lower:
        summary = "Inbox rule created"
    elif "set-inboxrule" in operation_lower or "updateinboxrules" in operation_lower:
        summary = "Inbox rule modified"
    elif "remove-inboxrule" in operation_lower:
        summary = "Inbox rule removed"
    elif "mailitemsaccessed" in operation_lower:
        mail_access_type = row.get("MailAccessType", "")
        summary = f"Mailbox items accessed ({mail_access_type})" if mail_access_type else "Mailbox items accessed"
    elif "searchqueryinitiated" in operation_lower:
        summary = "Mailbox search performed"
    elif "harddelete" in operation_lower:
        summary = "Email items hard deleted"
    elif "softdelete" in operation_lower:
        summary = "Email items soft deleted"
    elif "filedownloaded" in operation_lower:
        file_name = row.get("SourceFileName", "")
        summary = f"File downloaded: {file_name}" if file_name else "File downloaded"
    elif "filesyncdownloadedfull" in operation_lower:
        file_name = row.get("SourceFileName", "")
        summary = f"File synced/downloaded: {file_name}" if file_name else "File synced/downloaded"
    elif "anonymouslinkcreated" in operation_lower:
        summary = "Anonymous sharing link created"
    elif "sharingset" in operation_lower:
        summary = "Sharing permissions changed"
    elif "userloggedinfailed" in operation_lower:
        summary = "Failed user login"
    elif "userloggedin" in operation_lower:
        summary = "Successful user login"
    else:
        summary = operation

    context = []

    if user:
        context.append(f"user={user}")

    if ip:
        context.append(f"ip={ip}")

    if workload:
        context.append(f"workload={workload}")

    if context:
        return f"{summary} | " + " | ".join(context)

    return summary


def create_investigation_timeline(combined):
    timeline = combined.copy()

    suspicion = timeline.apply(assess_suspicion, axis=1)
    timeline = pd.concat([timeline, suspicion], axis=1)

    timeline["Severity"] = timeline["Severity"].fillna("")
    timeline["SuspicionReason"] = timeline["SuspicionReason"].fillna("")

    timeline["EventSummary"] = timeline.apply(create_event_summary, axis=1)

    timeline = add_failed_logon_patterns(timeline)

    timeline = ensure_columns(timeline, TIMELINE_COLUMNS)

    timeline = timeline.sort_values(
        by="CreationDate",
        ascending=True,
        na_position="last",
    )

    return timeline


def create_suspicious_activity(timeline):
    suspicious = timeline[
        timeline["SuspicionScore"].fillna(0).astype(int) > 0
    ].copy()

    return ensure_columns(suspicious, SUSPICIOUS_ACTIVITY_COLUMNS)

def add_failed_logon_patterns(timeline):
    output = timeline.copy()

    failed_logons = output[
        output["Operation"].astype(str).str.lower() == "userloggedinfailed"
    ].copy()

    if failed_logons.empty:
        return output

    failed_counts = (
        failed_logons
        .groupby(["PrimaryUser", "NormalisedIPAddress"])
        .size()
        .reset_index(name="FailedLogonCount")
    )

    high_failed = failed_counts[failed_counts["FailedLogonCount"] >= 5]

    for _, row in high_failed.iterrows():
        user = row["PrimaryUser"]
        ip = row["NormalisedIPAddress"]
        count = row["FailedLogonCount"]

        mask = (
            (output["PrimaryUser"] == user)
            & (output["NormalisedIPAddress"] == ip)
            & (output["Operation"].astype(str).str.lower() == "userloggedinfailed")
        )

        output.loc[mask, "SuspicionScore"] = output.loc[mask, "SuspicionScore"].apply(
            lambda current: max(int(current), 70)
        )

        output.loc[mask, "Severity"] = output.loc[mask, "SuspicionScore"].apply(get_severity)

        output.loc[mask, "SuspicionReason"] = output.loc[mask, "SuspicionReason"].apply(
            lambda reason: (
                f"{reason}; Multiple failed logons from same IP ({count})"
                if reason
                else f"Multiple failed logons from same IP ({count})"
            )
        )

    return output



def build_potential_incident(
    user,
    pattern,
    severity,
    confidence_score,
    events,
    reason,
    time_window_minutes,
):
    return {
        "PrimaryUser": user,
        "Pattern": pattern,
        "Severity": severity,
        "ConfidenceScore": confidence_score,
        "FirstSeen": events["CreationDate"].min(),
        "LastSeen": events["CreationDate"].max(),
        "TimeWindowMinutes": time_window_minutes,
        "SupportingOperations": ", ".join(
            sorted(set(events["Operation"].dropna().astype(str)))
        ),
        "SupportingIPs": ", ".join(
            sorted(set(events["NormalisedIPAddress"].dropna().astype(str)))
        ),
        "EventCount": len(events),
        "Reason": reason,
    }

def find_events_within_time_window(user_events, operations, time_window_minutes):
    events = user_events[
        user_events["OperationLower"].isin(operations)
    ].copy()

    if events.empty:
        return pd.DataFrame()

    events["CreationDateParsed"] = pd.to_datetime(
        events["CreationDate"],
        errors="coerce",
        utc=True,
    )

    events = events.dropna(subset=["CreationDateParsed"])

    if events.empty:
        return pd.DataFrame()

    events = events.sort_values("CreationDateParsed")

    for _, start_event in events.iterrows():
        window_start = start_event["CreationDateParsed"]
        window_end = window_start + pd.Timedelta(minutes=time_window_minutes)

        window_events = events[
            (events["CreationDateParsed"] >= window_start)
            & (events["CreationDateParsed"] <= window_end)
        ]

        found_operations = set(window_events["OperationLower"].dropna())

        if all(operation in found_operations for operation in operations):
            return window_events.drop(columns=["CreationDateParsed"])

    return pd.DataFrame()

def detect_mass_downloads(user_events):
    downloads = user_events[
        user_events["OperationLower"] == "filedownloaded"
    ].copy()

    if downloads.empty:
        return pd.DataFrame()

    downloads["CreationDateParsed"] = pd.to_datetime(
        downloads["CreationDate"],
        errors="coerce",
        utc=True,
    )

    downloads = downloads.dropna(subset=["CreationDateParsed"])
    downloads = downloads.sort_values("CreationDateParsed")

    for _, event in downloads.iterrows():
        start = event["CreationDateParsed"]
        end = start + pd.Timedelta(minutes=15)

        window = downloads[
            (downloads["CreationDateParsed"] >= start)
            & (downloads["CreationDateParsed"] <= end)
        ]

        if len(window) >= 3:
            return window.drop(columns=["CreationDateParsed"])

    return pd.DataFrame()

def detect_download_and_recycle(user_events):
    operations = [
        "filedownloaded",
        "filerecycled",
    ]

    return find_events_within_time_window(
        user_events=user_events,
        operations=operations,
        time_window_minutes=60,
    )

def create_potential_incidents(combined):
    incidents = []

    work = combined.copy()
    work["OperationLower"] = work["Operation"].astype(str).str.lower()

    for user, user_events in work.groupby("PrimaryUser"):
        if not user:
            continue

        # Potential BEC:
        # MailItemsAccessed + Inbox rule activity within 60 minutes
        bec_events = find_events_within_time_window(
            user_events=user_events,
            operations=[
                "mailitemsaccessed",
                "new-inboxrule",
            ],
            time_window_minutes=60,
        )

        if bec_events.empty:
            bec_events = find_events_within_time_window(
                user_events=user_events,
                operations=[
                    "mailitemsaccessed",
                    "set-inboxrule",
                ],
                time_window_minutes=60,
            )

        if bec_events.empty:
            bec_events = find_events_within_time_window(
                user_events=user_events,
                operations=[
                    "mailitemsaccessed",
                    "updateinboxrules",
                ],
                time_window_minutes=60,
            )

        if not bec_events.empty:
            incidents.append(
                build_potential_incident(
                    user=user,
                    pattern="BEC-Related Activity",
                    severity="Critical",
                    confidence_score=95,
                    events=bec_events,
                    reason="Mailbox access and inbox rule activity observed within 60 minutes. Analyst review recommended.",
                    time_window_minutes=60,
                )
            )

        # Potential Mailbox Cleanup:
        # MailItemsAccessed + HardDelete/SoftDelete within 60 minutes
        cleanup_events = find_events_within_time_window(
            user_events=user_events,
            operations=[
                "mailitemsaccessed",
                "harddelete",
            ],
            time_window_minutes=60,
        )

        if cleanup_events.empty:
            cleanup_events = find_events_within_time_window(
                user_events=user_events,
                operations=[
                    "mailitemsaccessed",
                    "softdelete",
                ],
                time_window_minutes=60,
            )

        if cleanup_events.empty:
            cleanup_events = find_events_within_time_window(
                user_events=user_events,
                operations=[
                    "mailitemsaccessed",
                    "movetodeleteditems",
                ],
                time_window_minutes=60,
            )

        if not cleanup_events.empty:
            incidents.append(
                build_potential_incident(
                    user=user,
                    pattern="Mailbox Cleanup Activity",
                    severity="High",
                    confidence_score=85,
                    events=cleanup_events,
                    reason="Mailbox access and email deletion activity observed within 60 minutes. Analyst review recommended.",
                    time_window_minutes=60,
                )
            )

        # Potential Data Exfiltration:
        # File download/sync + sharing activity within 120 minutes
        data_exfil_events = find_events_within_time_window(
            user_events=user_events,
            operations=[
                "filedownloaded",
                "anonymouslinkcreated",
            ],
            time_window_minutes=120,
        )

        if data_exfil_events.empty:
            data_exfil_events = find_events_within_time_window(
                user_events=user_events,
                operations=[
                    "filesyncdownloadedfull",
                    "anonymouslinkcreated",
                ],
                time_window_minutes=120,
            )

        if data_exfil_events.empty:
            data_exfil_events = find_events_within_time_window(
                user_events=user_events,
                operations=[
                    "filedownloaded",
                    "sharingset",
                ],
                time_window_minutes=120,
            )

        if data_exfil_events.empty:
            data_exfil_events = find_events_within_time_window(
                user_events=user_events,
                operations=[
                    "filesyncdownloadedfull",
                    "sharingset",
                ],
                time_window_minutes=120,
            )

        if not data_exfil_events.empty:
            incidents.append(
                build_potential_incident(
                    user=user,
                    pattern="Potential Data Exfiltration",
                    severity="High",
                    confidence_score=85,
                    events=data_exfil_events,
                    reason="File download or sync activity and sharing activity observed for the same user within 120 minutes.",
                    time_window_minutes=120,
                )
            )

        # Potential Password Spray / Brute Force:
        # 5+ failed logons for the same user within 30 minutes
        failed_logons = user_events[
            user_events["OperationLower"] == "userloggedinfailed"
        ].copy()

        if not failed_logons.empty:
            failed_logons["CreationDateParsed"] = pd.to_datetime(
                failed_logons["CreationDate"],
                errors="coerce",
                utc=True,
            )

            failed_logons = failed_logons.dropna(subset=["CreationDateParsed"])
            failed_logons = failed_logons.sort_values("CreationDateParsed")

            for _, start_event in failed_logons.iterrows():
                window_start = start_event["CreationDateParsed"]
                window_end = window_start + pd.Timedelta(minutes=30)

                window_events = failed_logons[
                    (failed_logons["CreationDateParsed"] >= window_start)
                    & (failed_logons["CreationDateParsed"] <= window_end)
                ]

                if len(window_events) >= 5:
                    incidents.append(
                        build_potential_incident(
                            user=user,
                            pattern="Potential Password Spray / Brute Force",
                            severity="High",
                            confidence_score=75,
                            events=window_events.drop(columns=["CreationDateParsed"]),
                            reason="Five or more failed login events observed for the same user within 30 minutes.",
                            time_window_minutes=30,
                        )
                    )
                    break
		
	# Mass file download detection

        mass_download_events = detect_mass_downloads(user_events)

        if not mass_download_events.empty:
            incidents.append(
                build_potential_incident(
                    user=user,
                    pattern="Potential Data Exfiltration",
                    severity="High",
                    confidence_score=80,
                    events=mass_download_events,
                    reason="Multiple file downloads observed within 15 minutes. Review recommended.",
                    time_window_minutes=15,
                )
            )

        # Download and recycle detection

        recycle_events = detect_download_and_recycle(user_events)

        if not recycle_events.empty:
            incidents.append(
                build_potential_incident(
                    user=user,
                    pattern="Potential Data Exfiltration",
                    severity="High",
                    confidence_score=85,
                    events=recycle_events,
                    reason="File download and recycle activity observed within 60 minutes. Review recommended.",
                    time_window_minutes=60,
                )
            )

    if not incidents:
        return pd.DataFrame(columns=POTENTIAL_INCIDENTS_COLUMNS)

    output = pd.DataFrame(incidents)
    return ensure_columns(output, POTENTIAL_INCIDENTS_COLUMNS)

def count_operations(df, operations):
    return len(
        df[
            df["Operation"]
            .astype(str)
            .str.lower()
            .isin([operation.lower() for operation in operations])
        ]
    )


def get_highest_severity(values):
    severity_rank = {
        "Critical": 4,
        "High": 3,
        "Medium": 2,
        "Low": 1,
        "": 0,
    }

    values = [str(value) for value in values if str(value).strip()]

    if not values:
        return ""

    return max(values, key=lambda value: severity_rank.get(value, 0))


def create_investigation_summary(
    combined,
    investigation_timeline,
    suspicious_activity,
    potential_incidents,
):
    primary_users = sorted(
        set(combined["PrimaryUser"].dropna().astype(str)) -
        {""}
    )

    unique_ips = sorted(
        set(combined["NormalisedIPAddress"].dropna().astype(str)) -
        {""}
    )

    first_activity = combined["CreationDate"].min()
    last_activity = combined["CreationDate"].max()

    try:
        first_dt = pd.to_datetime(first_activity, errors="coerce", utc=True)
        last_dt = pd.to_datetime(last_activity, errors="coerce", utc=True)
        duration_minutes = int((last_dt - first_dt).total_seconds() / 60)
    except Exception:
        duration_minutes = ""

    indicators = []

    if count_operations(combined, ["New-InboxRule", "Set-InboxRule", "UpdateInboxRules"]) > 0:
        indicators.append("Inbox Rules")

    if count_operations(combined, ["MailItemsAccessed"]) > 0:
        indicators.append("Mailbox Access")

    if count_operations(combined, ["SearchQueryInitiated"]) > 0:
        indicators.append("Mailbox Search")

    if count_operations(combined, ["HardDelete", "SoftDelete", "MoveToDeletedItems"]) > 0:
        indicators.append("Mailbox Deletion")

    if count_operations(combined, ["FileDownloaded", "FileSyncDownloadedFull"]) > 0:
        indicators.append("File Download")

    if count_operations(combined, ["FileRecycled"]) > 0:
        indicators.append("File Recycled")

    if count_operations(combined, ["AnonymousLinkCreated", "SharingSet"]) > 0:
        indicators.append("Sharing or anonymous Links")

    if count_operations(combined, ["Send"]) > 0:
        indicators.append("Emails Sent")

    if count_operations(combined, ["UserLoggedInFailed"]) > 0:
        indicators.append("Failed Logins")

    if len(potential_incidents) > 0:
        indicators.append("Potential Incidents")

    unmanaged_count = len(
        combined[
            combined.get("IsManagedDevice", pd.Series([""] * len(combined)))
            .astype(str)
            .str.lower()
            == "false"
        ]
    )

    if unmanaged_count > 0:
        indicators.append("Unmanaged Device")

    highest_severity = get_highest_severity(
        list(suspicious_activity.get("Severity", [])) +
        list(potential_incidents.get("Severity", []))
    )

    top_incident = ""
    top_incident_severity = ""

    if not potential_incidents.empty:
       ranked_incidents = potential_incidents.copy()
       ranked_incidents["SeverityRank"] = ranked_incidents["Severity"].map(
           {
                "Critical": 4,
                "High": 3,
                "Medium": 2,
                "Low": 1,
           }
        ).fillna(0)

       ranked_incidents = ranked_incidents.sort_values(
            by=["SeverityRank", "ConfidenceScore"],
            ascending=False,
        )

       top_incident = ranked_incidents.iloc[0]["Pattern"]
       top_incident_severity = ranked_incidents.iloc[0]["Severity"]

    summary_rows = [
        [
             "Primary User" if len(primary_users) == 1 else "Primary Users",
             ", ".join(primary_users),
        ],
        ["First Activity", first_activity],
        ["Last Activity", last_activity],
        ["Activity Duration Minutes", duration_minutes],
        ["Unique IP Count", len(unique_ips)],
        ["Unique IPs", ", ".join(unique_ips)],
        ["Potential Incidents", len(potential_incidents)],
        ["Top Incident", top_incident],
        ["Top Incident Severity", top_incident_severity],
        ["Suspicious Activity Events", len(suspicious_activity)],
        ["Highest Severity", highest_severity],
        ["Successful Logins", count_operations(combined, ["UserLoggedIn"])],
        ["Failed Logins", count_operations(combined, ["UserLoggedInFailed"])],
        ["Unmanaged Device Events", unmanaged_count],
        ["MailItemsAccessed Events", count_operations(combined, ["MailItemsAccessed"])],
        ["Inbox Rule Events", count_operations(combined, ["New-InboxRule", "Set-InboxRule", "UpdateInboxRules"])],
        ["Mailbox Search Events", count_operations(combined, ["SearchQueryInitiated"])],
        ["Emails Sent", count_operations(combined, ["Send"])],
        ["Hard Deletes", count_operations(combined, ["HardDelete"])],
        ["Soft Deletes", count_operations(combined, ["SoftDelete"])],
        ["Files Accessed", count_operations(combined, ["FileAccessed"])],
        ["Files Downloaded", count_operations(combined, ["FileDownloaded", "FileSyncDownloadedFull"])],
        ["Files Recycled", count_operations(combined, ["FileRecycled"])],
        ["Sharing Events", count_operations(combined, ["AnonymousLinkCreated", "SharingSet"])],
        ["Investigation Indicators", "; ".join(indicators)],
    ]

    return pd.DataFrame(summary_rows, columns=INVESTIGATION_SUMMARY_COLUMNS)

def main():
    OUTPUT_FILE.parent.mkdir(exist_ok=True)

    if not INPUT_FILE.exists():
        raise FileNotFoundError(f"Input file not found: {INPUT_FILE}")

    df = pd.read_csv(INPUT_FILE, dtype=str)

    if "AuditData" not in df.columns:
        raise ValueError("The CSV does not contain an 'AuditData' column.")

    missing_base_columns = [col for col in BASE_COLUMNS if col not in df.columns]
    if missing_base_columns:
        raise ValueError(f"Missing expected base columns: {missing_base_columns}")

    parsed_df = pd.json_normalize(df["AuditData"].apply(parse_audit_data))
    combined = pd.concat([df[BASE_COLUMNS].copy(), parsed_df], axis=1)
    combined = combined.loc[:, ~combined.columns.duplicated()]

    combined["MailAccessType"] = combined.apply(
        lambda row: row.get("MailAccessType")
        if pd.notna(row.get("MailAccessType")) and str(row.get("MailAccessType")).strip()
        else extract_operation_property(row, "MailAccessType"),
        axis=1,
    )

    combined = normalise_mailitemsaccessed_sync_fields(combined)

    combined["NormalisedIPAddress"] = combined.apply(
        lambda row: get_first_value(row, IP_FIELDS), axis=1
    )
    combined["IPAddressSource"] = combined.apply(
        lambda row: get_first_field_name(row, IP_FIELDS), axis=1
    )
    combined["PrimaryUser"] = combined.apply(
        lambda row: get_first_value(row, USER_FIELDS), axis=1
    )
    combined["PrimaryUserSource"] = combined.apply(
        lambda row: get_first_field_name(row, USER_FIELDS), axis=1
    )
    combined["EventTimestamp"] = combined.apply(
        lambda row: get_first_value(row, TIMESTAMP_FIELDS), axis=1
    )
    combined["TimestampSource"] = combined.apply(
        lambda row: get_first_field_name(row, TIMESTAMP_FIELDS), axis=1
    )
    combined["ParserConnector"] = combined.apply(classify_workload, axis=1)

    parser_errors = df.copy()
    parser_errors["ParserError"] = parser_errors["AuditData"].apply(parse_audit_error)
    parser_errors = parser_errors[parser_errors["ParserError"] != ""]

    workload_summary = (
        combined["ParserConnector"]
        .value_counts()
        .reset_index()
        .rename(columns={"ParserConnector": "Connector", "count": "Count"})
    )

    ip_analysis = create_ip_analysis(combined)

    investigation_timeline = create_investigation_timeline(combined)
    suspicious_activity = create_suspicious_activity(investigation_timeline)
    potential_incidents = create_potential_incidents(combined)

    investigation_summary = create_investigation_summary(
    	combined,
    	investigation_timeline,
    	suspicious_activity,
    	potential_incidents,
    )

    mail_items_accessed = combined[
        combined["Operation"].astype(str).str.lower() == "mailitemsaccessed"
    ].copy()

    mail_items_bind = mail_items_accessed[
        mail_items_accessed["MailAccessType"].astype(str).str.lower() == "bind"
    ].copy()

    mail_items_sync = mail_items_accessed[
        mail_items_accessed["MailAccessType"].astype(str).str.lower() == "sync"
    ].copy()

    mail_items_bind = add_email_item_columns(mail_items_bind)
    bind_email_columns = get_dynamic_email_columns(mail_items_bind)

    mail_items_bind_output = ensure_columns(
        mail_items_bind,
        MAIL_ITEMS_ACCESSED_BIND_COLUMNS + bind_email_columns,
    )

    mail_items_sync_output = ensure_columns(
        mail_items_sync,
        MAIL_ITEMS_ACCESSED_SYNC_COLUMNS,
    )

    exchange_investigation = combined[
        (combined["ParserConnector"] == "Exchange")
        & (combined["Operation"].astype(str).str.lower() != "mailitemsaccessed")
    ].copy()

    exchange_investigation = add_email_item_columns(exchange_investigation)
    exchange_email_columns = get_dynamic_email_columns(exchange_investigation)

    exchange_investigation_output = ensure_columns(
        exchange_investigation,
        EXCHANGE_INVESTIGATION_COLUMNS + exchange_email_columns,
    )

    inbox_rule_operations = [
        "new-inboxrule",
        "set-inboxrule",
        "updateinboxrules",
        "remove-inboxrule",
        "disable-inboxrule",
        "enable-inboxrule",
    ]

    inbox_rules = combined[
        combined["Operation"]
        .astype(str)
        .str.lower()
        .isin(inbox_rule_operations)
    ].copy()

    inbox_rules = normalise_inbox_rule_fields(inbox_rules)

    inbox_rules_output = ensure_columns(
        inbox_rules,
        INBOX_RULES_COLUMNS,
    )

    spod_output = ensure_columns(
        combined[combined["ParserConnector"] == "SharePoint-OneDrive"].copy(),
        SPOD_INVESTIGATION_COLUMNS,
    )

    azure_ad_events = combined[
        (combined["ParserConnector"] == "AzureAD")
        | (
            combined["Operation"]
            .astype(str)
            .str.lower()
            .isin(["userloggedin", "userloggedinfailed"])
        )
    ].copy()

    azure_ad_output = ensure_columns(
        azure_ad_events,
        AZURE_AD_INVESTIGATION_COLUMNS,
    )

    teams_output = combined[
        combined["ParserConnector"] == "Teams"
    ].copy()

    stats = pd.DataFrame(
    {
        "Metric": [
            "Total Events",
            "Investigation Timeline Events",
            "Suspicious Activity Events",
            "Potential Incidents",
            "Exchange Investigation Events",
            "Inbox Rule Events",
            "SharePoint-OneDrive Investigation Events",
            "AzureAD Investigation Events",
            "Teams Events",
            "Unknown-Unparsed Events",
            "Events With IP Address",
            "Events Without IP Address",
            "Unique IP Addresses",
            "Events With Primary User",
            "Events Without Primary User",
            "Events With Timestamp",
            "Events Without Timestamp",
            "JSON Parse Errors",
            "MailItemsAccessed Total",
            "MailItemsAccessed Bind",
            "MailItemsAccessed Sync",
        ],
        "Count": [
            len(combined),
            len(investigation_timeline),
            len(suspicious_activity),
            len(potential_incidents),
            len(exchange_investigation),
            len(inbox_rules),
            len(spod_output),
            len(azure_ad_events),
            len(teams_output),
            len(combined[combined["ParserConnector"] == "Unknown-Unparsed"]),
            len(combined[combined["NormalisedIPAddress"] != ""]),
            len(combined[combined["NormalisedIPAddress"] == ""]),
            len(ip_analysis),
            len(combined[combined["PrimaryUser"] != ""]),
            len(combined[combined["PrimaryUser"] == ""]),
            len(combined[combined["EventTimestamp"] != ""]),
            len(combined[combined["EventTimestamp"] == ""]),
            len(parser_errors),
            len(mail_items_accessed),
            len(mail_items_bind),
            len(mail_items_sync),
        ],
    }
)

    with pd.ExcelWriter(OUTPUT_FILE, engine="openpyxl") as writer:
        stats.to_excel(writer, sheet_name="Parser Statistics", index=False)
        investigation_summary.to_excel(writer, sheet_name="Investigation-Summary", index=False)
        workload_summary.to_excel(writer, sheet_name="Workload Summary", index=False)
        ip_analysis.to_excel(writer, sheet_name="IP-Analysis", index=False)
        investigation_timeline.to_excel(writer, sheet_name="Investigation-Timeline", index=False)
        suspicious_activity.to_excel(writer, sheet_name="Suspicious-Activity", index=False)
        potential_incidents.to_excel(writer, sheet_name="Potential-Incidents", index=False)
        combined.to_excel(writer, sheet_name="All Events", index=False)
        parser_errors.to_excel(writer, sheet_name="Parser Errors", index=False)

        azure_ad_output.to_excel(writer, sheet_name="AzureAD-Investigation", index=False)
        exchange_investigation_output.to_excel(writer, sheet_name="Exchange-Investigation", index=False)
        inbox_rules_output.to_excel(writer, sheet_name="InboxRules", index=False)
        mail_items_bind_output.to_excel(writer, sheet_name="MailItemsAccessed-Bind", index=False)
        mail_items_sync_output.to_excel(writer, sheet_name="MailItemsAccessed-Sync", index=False)
        spod_output.to_excel(writer, sheet_name="SPOD-Investigation", index=False)
        teams_output.to_excel(writer, sheet_name="Teams", index=False)

    print(f"Done. Output created: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()