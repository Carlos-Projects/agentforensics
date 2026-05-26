"""Compare actual agent behaviour against an expected policy."""

from __future__ import annotations

from typing import Any


def diff_behavior(
    actual: list[dict[str, Any]],
    expected: list[dict[str, Any]] | None = None,
    policy: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Compare observed agent behaviour to expected actions.

    Detects:
    - Extra actions that are not in the expected sequence
    - Missing actions that should have occurred
    - Actions performed in the wrong order
    - Policy violations (when *policy* is supplied)

    Args:
        actual: Observed agent actions (chronological).
        expected: Expected action sequence (optional).
        policy: Allowed/blocked policy rules (optional).

    Returns:
        List of deviation dictionaries::

            {
                "type": "extra_action" | "missing_action" | "wrong_order" | "policy_violation",
                "actual_event":  dict or None,
                "expected_event": dict or None,
                "description": str,
            }
    """
    deviations: list[dict[str, Any]] = []

    # --- Extra / missing / order diff ---
    if expected is not None:
        actual_types = [e.get("event_type", "") for e in actual]
        expected_types = [e.get("event_type", "") for e in expected]

        # Missing actions
        for i, exp in enumerate(expected_types):
            count_actual = actual_types.count(exp)
            count_expected = expected_types.count(exp)
            if count_actual < count_expected:
                already_reported = any(
                    d["type"] == "missing_action" and d.get("expected_event", {}).get("event_type") == exp
                    for d in deviations
                )
                if not already_reported:
                    deviations.append(
                        {
                            "type": "missing_action",
                            "actual_event": None,
                            "expected_event": expected[i],
                            "description": f"Expected action '{exp}' was not performed by the agent",
                        }
                    )

        # Extra actions
        for _i, ev in enumerate(actual):
            if ev.get("event_type") not in expected_types:
                deviations.append(
                    {
                        "type": "extra_action",
                        "actual_event": ev,
                        "expected_event": None,
                        "description": f"Unexpected action '{ev.get('event_type', '?')}' performed by agent",
                    }
                )

    # --- Policy violations ---
    if policy:
        blocked_tools: list[str] = policy.get("blocked_tools", [])
        blocked_paths: list[str] = policy.get("blocked_paths", [])
        max_risk: float = float(policy.get("max_risk_score", 1.0))

        for ev in actual:
            target = ev.get("target", "")
            event_type = ev.get("event_type", "")
            risk_score = float(ev.get("risk_score", 0))
            description = ev.get("description", "")

            # Check blocked tools
            if event_type in blocked_tools:
                deviations.append(
                    {
                        "type": "policy_violation",
                        "actual_event": ev,
                        "expected_event": None,
                        "description": f"Agent used blocked tool '{event_type}'",
                    }
                )

            # Check blocked paths / targets
            for blocked in blocked_paths:
                if blocked.lower() in target.lower() or blocked.lower() in description.lower():
                    deviations.append(
                        {
                            "type": "policy_violation",
                            "actual_event": ev,
                            "expected_event": None,
                            "description": f"Agent accessed blocked target '{blocked}'",
                        }
                    )
                    break

            # Check risk threshold
            if risk_score > max_risk:
                deviations.append(
                    {
                        "type": "policy_violation",
                        "actual_event": ev,
                        "expected_event": None,
                        "description": f"Risk score {risk_score:.1f} exceeds policy limit {max_risk}",
                    }
                )

    return deviations
