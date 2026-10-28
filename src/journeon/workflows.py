# SPDX-License-Identifier: AGPL-3.0-only
"""Provider-neutral workflow definitions; the configured check supplies exact proof."""

from journeon.contracts import TaskWorkflow, WorkflowTemplate, WorkflowTemplates


def templates() -> WorkflowTemplates:
    definitions = {
        "Single Agent": [("work", "WORK"), ("verify", "VERIFICATION")],
        "Implement + Review": [
            ("implement", "WORK"),
            ("review", "REVIEW"),
            ("verify", "VERIFICATION"),
        ],
        "Research + Synthesize": [
            ("research", "WORK"),
            ("synthesize", "WORK"),
            ("verify", "VERIFICATION"),
        ],
        "Parallel Exploration": [
            ("explore-a", "WORK"),
            ("explore-b", "WORK"),
            ("synthesize", "WORK"),
            ("verify", "VERIFICATION"),
        ],
        "Plan + Execute": [("plan", "WORK"), ("execute", "WORK"), ("verify", "VERIFICATION")],
        "Test/Fix": [("test", "VERIFICATION"), ("fix", "WORK"), ("verify", "VERIFICATION")],
        "Design + Implement + Review": [
            ("design", "WORK"),
            ("implement", "WORK"),
            ("review", "REVIEW"),
            ("verify", "VERIFICATION"),
        ],
        "Hardened Build": [
            ("recon", "WORK"),
            ("plan", "WORK"),
            ("plan-review", "REVIEW"),
            ("build", "WORK"),
            ("verify", "VERIFICATION"),
            ("fresh-inspection", "REVIEW"),
            ("close", "WORK"),
        ],
    }
    result = []
    for name, sequence in definitions.items():
        steps = []
        for index, (identity, kind) in enumerate(sequence):
            dependencies = [sequence[index - 1][0]] if index else []
            if name == "Parallel Exploration":
                dependencies = (
                    []
                    if index < 2
                    else ["explore-a", "explore-b"]
                    if index == 2
                    else ["synthesize"]
                )
            steps.append(
                {
                    "step_id": identity,
                    "kind": kind,
                    "dependencies": dependencies,
                    "check_id": "check" if kind == "VERIFICATION" else None,
                }
            )
        result.append(
            WorkflowTemplate(name=name, workflow=TaskWorkflow.model_validate({"steps": steps}))
        )
    return WorkflowTemplates(templates=result)
