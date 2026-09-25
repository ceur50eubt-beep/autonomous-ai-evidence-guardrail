package guardrail.blast_radius_test

import data.guardrail.blast_radius

test_allow_safe_request {
blast_radius.allow with input as {
"target_env": "production",
"action_payload": {
"action": "cloudwatch:GetMetricData",
"command": "aws cloudwatch get-metric-data"
},
"context": {"security_approved": false}
}
}

test_deny_destructive_command {
not blast_radius.allow with input as {
"target_env": "production",
"action_payload": {
"action": "rds:ExecuteStatement",
"command": "DROP TABLE prod_users;"
},
"context": {"security_approved": false}
}
}
