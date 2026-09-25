package guardrail.blast_radius

import future.keywords.in

default allow = false
default deny_reasons = []

destructive_keywords := [
    "drop table", "drop database", "truncate", "rm -rf",
    "delete from", "deletevpc", "terminateinstances", "deletecluster"
]

allow {
    count(deny_reasons) == 0
}

deny_reasons[msg] {
    input.target_env == "production"
    some keyword in destructive_keywords
    contains(lower(input.action_payload.command), keyword)
    msg := sprintf("Destructive command '%v' is strictly prohibited in production environment", [keyword])
}

deny_reasons[msg] {
    dangerous_iam_actions := ["iam:PutRolePolicy", "iam:AttachRolePolicy", "iam:CreateAccessKey"]
    input.action_payload.action in dangerous_iam_actions
    not input.context.security_approved
    msg := sprintf("IAM privilege escalation attempt '%v' blocked without Security Approval", [input.action_payload.action])
}
