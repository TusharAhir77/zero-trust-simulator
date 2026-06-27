# Zero Trust Policy — Every role has limited access
POLICIES = {
    "admin":  ["server1", "server2", "database", "logs", "reports"],
    "user":   ["server1", "reports"],
    "guest":  []  # Guest has NO access
}

def check_access(role, resource):
    allowed_resources = POLICIES.get(role, [])
    if resource in allowed_resources:
        return True, f"✅ ACCESS GRANTED — {resource}"
    return False, f"❌ ACCESS DENIED — {resource}"