"""Controlled ablation: per-resource authorization without ancestry or denial memory.

This deliberately narrow baseline is *not* representative of all stateless
systems. It uses the same trusted policy config and exact scoped approvals as
RuntimeGuard, but examines only the requested document's current classification.
The simulator intentionally marks newly derived documents 'public', so this
ablation tests whether omission of trusted ancestry changes outcomes.
"""
from __future__ import annotations
from .runtime_guard import Decision, RuntimeGuard, _EFFECTS


class StatelessResourceGuard(RuntimeGuard):
    def acknowledge_denial(self, action: dict, code: str, state: dict) -> None:
        # Absence of persistent denial history is the ablation, not an oversight.
        return None

    def check(self, action: dict, state: dict) -> Decision:
        if not isinstance(action, dict) or not isinstance(state, dict):
            return Decision(False, 'invalid_action_or_state', 'unknown', '')
        tool, args = action.get('tool', ''), action.get('args', {})
        if not isinstance(args, dict) or tool not in _EFFECTS:
            return Decision(False, 'unknown_tool_or_effect', 'unknown', '')
        effect = _EFFECTS[tool]
        if effect != 'document_release':
            # Preserve ordinary operational controls and resource checks.
            return super().check(action, state)
        name, dest = args.get('doc'), args.get('destination')
        if not isinstance(name, str) or not name:
            return Decision(False, 'unresolved_resource', effect, str(name or ''))
        record = state.get('documents', {}).get(name)
        if not isinstance(record, dict):
            return Decision(False, 'unresolved_resource', effect, name)
        classification = record.get('classification')
        if not isinstance(classification, str) or not classification.strip():
            return Decision(False, 'invalid_classification', effect, name)
        classification = classification.strip().lower()
        cfg = self.policy['document_release']
        if classification not in cfg['known_classifications']:
            return Decision(False, 'unknown_classification', effect, name)
        if not isinstance(dest, str) or dest not in set(cfg['external_destinations']) | {'internal'}:
            return Decision(False, 'unknown_destination', effect, name)
        if dest == 'internal':
            return Decision(True, 'internal_release_allowed', effect, name)
        if classification in cfg['restricted_classifications'] and cfg['require_verified_release_approval']:
            if not self._verified_release_approved(state, name, dest):
                return Decision(False, 'direct_resource_restricted_without_approval', effect, name)
        return Decision(True, 'direct_resource_release_allowed_no_ancestry', effect, name)
