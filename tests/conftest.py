import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def make_iban(country: str, bban: str) -> str:
    digits = "".join(str(int(c, 36)) for c in bban + country + "00")
    return f"{country}{98 - int(digits) % 97:02d}{bban}"


TOOLS = [
    {"name": "read_inbox", "parameters": {"type": "object", "properties": {"limit": {"type": "integer"}}}},
    {"name": "list_payees", "parameters": {"type": "object", "properties": {}}},
    {"name": "send_email", "parameters": {"type": "object", "properties": {
        "to": {"type": "array", "items": {"type": "string"}},
        "cc": {"type": "array", "items": {"type": "string"}},
        "bcc": {"type": "array", "items": {"type": "string"}},
        "subject": {"type": "string"}, "body": {"type": "string"},
        "attachments": {"type": "array", "items": {"type": "string"}}}}},
    {"name": "send_money", "parameters": {"type": "object", "properties": {
        "recipient": {"type": "string"}, "iban": {"type": "string"}, "amount": {"type": "number"},
        "currency": {"type": "string"}, "date": {"type": "string", "format": "date"},
        "recurring": {"type": "boolean", "default": False}, "memo": {"type": "string"}}}},
    {"name": "share_file", "parameters": {"type": "object", "properties": {
        "file_id": {"type": "string"}, "recipient": {"type": "string"},
        "permission": {"type": "string", "enum": ["view", "edit"], "default": "view"}}}},
    {"name": "execute_sql", "parameters": {"type": "object", "properties": {"query": {"type": "string"}}}},
    {"name": "fetch_url", "parameters": {"type": "object", "properties": {"url": {"type": "string"}}}},
]
