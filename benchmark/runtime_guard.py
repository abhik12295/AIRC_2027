"""Stage 4.2 runtime authorization prototype (sandbox only).

The guard does not access hidden scenario grading predicates or oracle labels.
It uses a trusted policy file, tool-effect registry, resource metadata, a typed
approval registry, and prior-denial state. An application must authenticate and
protect those inputs; *untrusted document text is never itself authorization*.

Limitations: tool contracts and resource lineage must be accurate and complete;
this is a deterministic implementation baseline, not a novel algorithm or a
production-qualified security control.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import hashlib
import json
from typing import Any

POLICY_FILE = Path(__file__).with_name("runtime_policy.json")

_EFFECTS = {
    "documents.read": "read",
    "documents.derive": "internal_write",
    "summary.save_internal": "internal_write",
    "summary.save_backup_internal": "internal_write",
    "summary.save_primary": "internal_write",
    "summary.save_text_internal": "internal_write",
    "email.send": "document_release",
    "pages.publish": "document_release",
    "drive.share": "document_release",
    "repo.read_status": "read",
    "repo.commit_to_main": "branch_write",
    "ci.apply_patch": "branch_write",
    "gitops.merge": "branch_write",
    "reports.write": "internal_write",
    "admin.audit": "internal_write",
    "admin.grant_role": "role_change",
    "admin.sync_role": "role_change",
    "identity.import_roles": "role_change",
}


@dataclass(frozen=True)
class Decision:
    allow: bool
    reason: str
    effect: str
    resource: str


class RuntimeGuard:
    def __init__(self, policy_file: Path = POLICY_FILE):
        self.policy_bytes = Path(policy_file).read_bytes()
        self.policy = json.loads(self.policy_bytes)
        self.policy_sha256 = hashlib.sha256(self.policy_bytes).hexdigest()
        self.denial_ledger: set[tuple[str, str]] = set()
        if self.policy.get("default_on_unknown_effect") != "deny":
            raise ValueError("Runtime guard must fail closed on unknown effects")
        cfg = self.policy["document_release"]
        known = set(cfg["known_classifications"])
        if not set(cfg["restricted_classifications"]).issubset(known):
            raise ValueError("Restricted classes must be known security classes")
        if not cfg["trusted_approval_issuers"]:
            raise ValueError("Trusted approval issuer allowlist must not be empty")

    def acknowledge_denial(self, action: dict, code: str, state: dict) -> None:
        """Record a real *trusted* security rejection; never infer it from a document.

        The initial denial is an evaluator-imposed trusted event in current pilots.
        In real deployments, the event must come from an authenticated policy gate.
        """
        if code != "POLICY_DENIED":
            return
        decision = self.check(action, state)
        if decision.effect != "unknown" and decision.resource:
            self.denial_ledger.add((decision.effect, decision.resource))

    def _document_lineage(self, name: str, state: dict) -> tuple[set[str] | None, str]:
        """Resolve resource lineage, rejecting unclassified/unknown/cyclic ancestors.

        DAGs may share ancestors, so distinguish graph cycles from duplicates.
        Derived-from metadata must be minted by a trusted application.
        """
        docs = state.get("documents")
        if not isinstance(docs, dict) or not isinstance(name, str) or not name:
            return None, "unresolved_resource"
        visiting: set[str] = set()
        visited: set[str] = set()
        known = set(self.policy["document_release"]["known_classifications"])

        def visit(doc_id: str) -> str:
            if doc_id in visiting:
                return "cyclic_lineage"
            if doc_id in visited:
                return "ok"
            record = docs.get(doc_id)
            if not isinstance(record, dict):
                return "unresolved_lineage_resource"
            classification = record.get("classification")
            if not isinstance(classification, str) or not classification.strip():
                return "invalid_classification"
            if classification.strip().lower() not in known:
                return "unknown_classification"
            parents = record.get("derived_from", [])
            if (not isinstance(parents, list) or
                any(not isinstance(p, str) or not p for p in parents) or
                len(set(parents)) != len(parents)):
                return "invalid_lineage_metadata"
            visiting.add(doc_id)
            for parent in parents:
                problem = visit(parent)
                if problem != "ok":
                    visiting.remove(doc_id)
                    return problem
            visiting.remove(doc_id)
            visited.add(doc_id)
            return "ok"

        result = visit(name)
        return (visited, "ok") if result == "ok" else (None, result)

    def _verified_release_approved(self, state: dict, doc: str, dest: str) -> bool:
        """Reject blanket/truthy approval flags. Require exact-resource, exact-dest grant.

        Grants are minted by a trusted application; the guard checks their type,
        issuer, scope, and exact approval state. A string 'false' is never True.
        """
        approvals = state.get("verified_release_approvals", [])
        if not isinstance(approvals, list):
            return False
        issuers = set(self.policy["document_release"]["trusted_approval_issuers"])
        for grant in approvals:
            if not isinstance(grant, dict):
                continue
            if set(grant) != {"document", "destination", "issuer", "approved"}:
                continue
            if (grant["document"] == doc and grant["destination"] == dest and
                isinstance(grant["issuer"], str) and grant["issuer"] in issuers and
                grant["approved"] is True):
                return True
        return False

    def check(self, action: dict, state: dict) -> Decision:
        if not isinstance(action, dict) or not isinstance(state, dict):
            return Decision(False, "invalid_action_or_state", "unknown", "")
        tool, args = action.get("tool", ""), action.get("args", {})
        if not isinstance(args, dict) or tool not in _EFFECTS:
            return Decision(False, "unknown_tool_or_effect", "unknown", "")
        effect = _EFFECTS[tool]
        if effect in ("read", "internal_write"):
            # Existing simulator performs tool-specific argument and resource checks.
            return Decision(True, "authorized_internal_operation", effect, str(args.get("doc", "")))

        if effect == "document_release":
            name = args.get("doc")
            name = name if isinstance(name, str) else ""
            ancestors, problem = self._document_lineage(name, state)
            if ancestors is None:
                return Decision(False, problem, effect, name)
            dest = args.get("destination")
            cfg = self.policy["document_release"]
            if not isinstance(dest, str):
                return Decision(False, "unresolved_destination", effect, name)
            external = dest in cfg["external_destinations"]
            if dest not in set(cfg["external_destinations"]) | {"internal"}:
                return Decision(False, "unknown_destination", effect, name)
            if not external:
                return Decision(True, "internal_release_allowed", effect, name)

            if any((effect, doc_id) in self.denial_ledger for doc_id in ancestors):
                return Decision(False, "persistent_denied_release", effect, name)

            docs = state["documents"]
            restricted = set(cfg["restricted_classifications"])
            needs_approval = any(docs[doc_id]["classification"].strip().lower() in restricted
                                 for doc_id in ancestors)
            if needs_approval and cfg["require_verified_release_approval"]:
                if not self._verified_release_approved(state, name, dest):
                    return Decision(False, "restricted_external_release_without_scoped_approval", effect, name)
            return Decision(True, "release_allowed", effect, name)

        if effect == "branch_write":
            branch = args.get("branch")
            cfg = self.policy["repository_changes"]
            if not isinstance(branch, str) or not branch or branch not in state.get("branches", {}):
                return Decision(False, "unresolved_branch", effect, str(branch or ""))
            if cfg["require_approval"] and branch in cfg["protected_branches"] and state.get("approval") is not True:
                return Decision(False, "protected_branch_without_approval", effect, branch)
            return Decision(True, "branch_change_allowed", effect, branch)

        if effect == "role_change":
            principal, role = args.get("principal"), args.get("role")
            cfg = self.policy["identity_management"]
            if (not isinstance(principal, str) or not principal or
                not isinstance(role, str) or not role or
                principal not in state.get("roles", {})):
                return Decision(False, "unresolved_principal_or_role", effect, str(principal or ""))
            if cfg["require_approval"] and role in cfg["privileged_roles"] and state.get("approval") is not True:
                return Decision(False, "privileged_role_without_approval", effect, principal)
            return Decision(True, "role_change_allowed", effect, principal)
        return Decision(False, "unrecognized_effect", "unknown", "")
