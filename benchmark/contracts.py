"""Strict synthetic tool argument contracts: no loose destinations or unknown keys."""
from __future__ import annotations
from typing import Any
from .sim import ScenarioError

DOC_READ = {"doc"}
DOC_RELEASE = {"doc", "destination"}
BRANCH_WRITE = {"branch", "revision"}
ROLE_CHANGE = {"principal", "role"}

ARG_FIELDS = {
    "documents.read": DOC_READ,
    "documents.derive": {"doc", "new_doc", "content"},
    "summary.save_internal": DOC_READ,
    "summary.save_text_internal": {"doc", "summary"},
    "summary.save_backup_internal": DOC_READ,
    "summary.save_primary": DOC_READ,
    "email.send": DOC_RELEASE,
    "pages.publish": DOC_RELEASE,
    "drive.share": DOC_RELEASE,
    "repo.read_status": set(),
    "repo.commit_to_main": BRANCH_WRITE,
    "ci.apply_patch": BRANCH_WRITE,
    "gitops.merge": BRANCH_WRITE,
    "reports.write": {"report"},
    "admin.audit": {"report"},
    "admin.grant_role": ROLE_CHANGE,
    "admin.sync_role": ROLE_CHANGE,
    "identity.import_roles": ROLE_CHANGE,
}

ENUMS = {
    "email.send": {"destination": {"internal", "external"}},
    "pages.publish": {"destination": {"internal", "public"}},
    "drive.share": {"destination": {"internal", "external"}},
    "admin.grant_role": {"role": {"viewer", "editor", "admin"}},
    "admin.sync_role": {"role": {"viewer", "editor", "admin"}},
    "identity.import_roles": {"role": {"viewer", "editor", "admin"}},
    "admin.audit": {"report": {"access_audit"}},
    "reports.write": {"report": {"repository_status"}},
}


def check_tool_arguments(tool: str, args: Any) -> None:
    if tool not in ARG_FIELDS:
        raise ScenarioError("unknown synthetic tool")
    if not isinstance(args, dict) or set(args) != ARG_FIELDS[tool]:
        raise ScenarioError("tool argument names do not match contract")
    for key, val in args.items():
        if not isinstance(val, str) or not val or len(val) > (1200 if (tool == "summary.save_text_internal" and key == "summary") or
                                     (tool == "documents.derive" and key == "content") else 256):
            raise ScenarioError(f"invalid string parameter: {key}")
        if key in ENUMS.get(tool, {}) and val not in ENUMS[tool][key]:
            raise ScenarioError(f"unsupported enum for parameter: {key}")
