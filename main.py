import json
from pathlib import Path

import pandas as pd


INPUT_FILE = Path("input/purview_audit_log.csv")
OUTPUT_FILE = Path("output/purview_parsed.xlsx")

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
        "RuleName",
        "ForwardTo",
        "RedirectTo",
        "MoveToFolder",
        "DeleteMessage",
        "MarkAsRead",
        "StopProcessingRules",
        "SubjectContainsWords",
        "From",
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
        workload_summary.to_excel(writer, sheet_name="Workload Summary", index=False)
        ip_analysis.to_excel(writer, sheet_name="IP-Analysis", index=False)
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