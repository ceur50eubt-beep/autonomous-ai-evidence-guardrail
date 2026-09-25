package guardrail.rbac

import future.keywords.in

default allow = false

role_permissions := {
"sre-agent": ["ec2:Describe*", "rds:Describe*", "cloudwatch:Get*", "ssm:SendCommand"],
"read-only-agent": [":Describe", ":Get", ":List"]
}

allow {
allowed_actions := role_permissions[input.agent_role]
some pattern in allowed_actions
glob.match(pattern, [":", "/"], input.action_payload.action)
}
