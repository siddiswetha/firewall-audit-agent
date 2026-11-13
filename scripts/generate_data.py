"""Generate synthetic data for firewall-audit-agent.

All rules, guidance summaries, and training examples are written here
from scratch. No real customer rules, no copied text. Guidance docs
paraphrase general firewall best practice (including concepts from
NIST SP 800-41) in original words.
Run: python scripts/generate_data.py
"""
import json
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
GUIDANCE = DATA / "guidance"

random.seed(42)

ADMIN_PORTS = {22, 3389, 5432, 3306, 6379, 27017, 1433}
WEB_PORTS = {80, 443}
COMMON_PORTS = [22, 3389, 80, 443, 53, 25, 5432, 3306, 8080, 8443, 6379, 27017, 1433, 21, 23]

SOURCES = [
    ("0.0.0.0/0", "internet"),
    ("0.0.0.0/0", "internet"),
    ("10.0.0.0/8", "internal"),
    ("192.168.1.0/24", "internal"),
    ("10.1.2.0/24", "internal"),
    ("10.1.2.3", "host"),
    ("10.1.2.4", "host"),
    ("203.0.113.10", "partner"),
    ("198.51.100.0/24", "partner"),
]
DESTS = [
    ("10.0.1.5", "server"),
    ("10.0.1.0/24", "subnet"),
    ("10.0.2.10", "db"),
    ("0.0.0.0/0", "any"),
    ("192.168.1.10", "server"),
    ("10.1.2.3", "host"),
]

GUIDANCE_DOCS = {
    "G01-least-privilege": (
        "Least privilege for firewall rules",
        """A firewall rule should allow only the traffic a service actually needs, and nothing more. "
        "Start from what the application requires: the exact source, the exact destination, the exact port and protocol. "
        "If a rule allows a whole network when one host would do, or a range of ports when one port would do, tighten it. "
        "Review broad rules on a schedule and remove rules that no longer have an owner or a business need. "
        "Least privilege is not a one-time setting; it is a habit of asking, for every allow rule, whether a narrower rule would still work.""",
    ),
    "G02-open-admin-ports": (
        "Do not expose admin ports to the internet",
        """Administrative services such as SSH on port 22 and remote desktop on port 3389 are frequent targets for automated login attempts. "
        "Exposing them to the whole internet greatly increases the chance of a brute-force attempt succeeding if a credential is weak or reused. "
        "Reach admin services only from a small set of trusted addresses, through a VPN or bastion host, with strong authentication. "
        "If an admin port must be reachable, restrict the source, log every attempt, and alert on repeated failures. "
        "An allow rule for port 22 or 3389 from 0.0.0.0/0 should be treated as high risk until it is narrowed or removed.""",
    ),
    "G03-broad-source": (
        "Overly broad sources",
        """A source of 0.0.0.0/0 means anyone on the internet can try to reach the destination. "
        "That is sometimes correct for a public web service on ports 80 or 443, but it is rarely correct for internal services, databases, or admin ports. "
        "Prefer a named network, a partner address range, or a single host. "
        "When a broad source is unavoidable, pair it with a narrow destination and port, and add logging and alerting so abuse is visible quickly.""",
    ),
    "G04-any-any": (
        "Any-to-any rules",
        """A rule that allows any source to any destination on any port defeats the purpose of a firewall. "
        "It hides the real traffic pattern, makes audits meaningless, and lets a single compromised host reach everything. "
        "Replace any-to-any rules with specific rules for each service, or at least split them by destination and port. "
        "If an any-to-any rule exists temporarily for troubleshooting, give it an expiry date, an owner, and a review date, and remove it promptly.""",
    ),
    "G05-egress": (
        "Control outbound traffic too",
        """Firewalls are often tuned only for inbound traffic, but outbound rules matter as well. "
        "A host that is compromised will often try to contact an external server, so allowing all outbound traffic makes that harder to spot. "
        "Allow outbound traffic only to the destinations and ports a service needs, such as a named update server or a specific API endpoint. "
        "Log outbound connections that are denied and review them; a sudden rise in denied outbound attempts can be an early sign of a problem.""",
    ),
    "G06-logging-monitoring": (
        "Logging and monitoring",
        """A rule without logging is hard to audit and hard to defend. "
        "Log allowed and denied connections for sensitive services, keep the logs long enough to investigate incidents, and monitor them rather than collecting them unread. "
        "Alert on repeated denied attempts, on first use of a rarely used rule, and on changes to the rule set itself. "
        "When a finding is raised, the log should be able to show whether the rule was actually used, by whom, and how often.""",
    ),
    "G07-default-deny": (
        "Default deny",
        """The safest starting position is to deny traffic by default and allow only what is explicitly needed. "
        "With default deny, a missing rule fails closed: traffic is blocked until someone reviews it and adds a deliberate allow rule. "
        "With default allow, a missing rule fails open and traffic flows unchecked. "
        "Document the default policy, make it visible to reviewers, and treat any exception to it as a decision that needs a reason and an owner.""",
    ),
    "G08-segmentation": (
        "Network segmentation",
        """Split a network into segments so that a problem in one segment does not automatically spread to the others. "
        "Keep databases in a segment that only application servers can reach, keep admin interfaces in a segment that only operators can reach, and keep user devices separate from servers. "
        "Firewall rules between segments should be explicit and narrow. "
        "Segmentation is a practical form of least privilege applied to the network layout itself.""",
    ),
    "G09-change-management": (
        "Change management and review",
        """Every firewall change should have a request, a reason, an owner, and a review. "
        "Record who asked for the rule, what service it supports, when it should be reviewed, and when it should expire. "
        "Review the full rule set on a regular cycle, remove stale rules, and check that each rule still matches its stated purpose. "
        "A rule with no owner and no review date is a candidate for removal.""",
    ),
    "G10-database-ports": (
        "Protect database ports",
        """Database ports such as 5432 for PostgreSQL, 3306 for MySQL, 1433 for SQL Server, 6379 for Redis, and 27017 for MongoDB should never be reachable from the internet. "
        "They should be reachable only from the specific application hosts that need them, on the specific network segment where the database lives. "
        "If a database port is exposed broadly, treat it as high risk: check whether data was accessed, narrow the source immediately, and add authentication and logging checks.""",
    ),
    "G11-dns-and-essential-services": (
        "Essential services need care too",
        """Some services, such as DNS on port 53, are easy to overlook because they are always needed. "
        "Allow DNS only to named resolvers, and do not allow a host to use any external resolver without a reason. "
        "The same care applies to other always-on services: allow the exact port and protocol, to the exact destination, and log unusual volumes that could indicate misuse.""",
    ),
    "G12-review-and-expiry": (
        "Review dates and expiry",
        """Firewall rules age badly. A rule that was correct for a migration or a test can linger for years after the work is done. "
        "Give every temporary rule an expiry date and every permanent rule a review date. "
        "At review, check that the service still exists, that the source is still correct, and that the port is still needed. "
        "Removing a stale rule is usually safer than leaving it in place.""",
    ),
    "G13-zero-trust": (
        "Zero trust in practice",
        """Zero trust means not granting access simply because a request comes from inside the network. "
        "Check identity, device, and need for every connection, even between internal segments. "
        "Use narrow firewall rules as one part of that check, alongside strong authentication, encryption, and logging. "
        "A rule that trusts a whole internal network without further checks is weaker than a rule that trusts one host for one service.""",
    ),
}


def severity_for(source, dest, port, action):
    if action == "deny":
        return "low"
    if source == "0.0.0.0/0" and dest == "0.0.0.0/0":
        return "high"
    if port == 0:
        return "high"
    if source == "0.0.0.0/0" and port in ADMIN_PORTS:
        return "high"
    if source in ("0.0.0.0/0", "198.51.100.0/24") and port in ADMIN_PORTS:
        return "high"
    if source == "0.0.0.0/0" and port not in WEB_PORTS:
        return "medium"
    if source == "0.0.0.0/0" and port in WEB_PORTS:
        return "low"
    if source in ("10.0.0.0/8", "192.168.1.0/24") and port in ADMIN_PORTS:
        return "medium"
    if dest == "0.0.0.0/0":
        return "medium"
    return "low"


def make_rules():
    rules = []
    # Hand-designed anchor cases first, so the set covers the interesting patterns.
    anchors = [
        ("10.1.2.3", "10.0.1.5", 22, "allow", "Admin SSH from a single operator host to a server"),
        ("0.0.0.0/0", "10.0.1.5", 22, "allow", "SSH open to the whole internet"),
        ("0.0.0.0/0", "10.0.2.10", 5432, "allow", "PostgreSQL open to the whole internet"),
        ("0.0.0.0/0", "0.0.0.0/0", 0, "allow", "Any source to any destination, any port"),
        ("0.0.0.0/0", "10.0.1.5", 443, "allow", "Public HTTPS to a web server"),
        ("10.0.0.0/8", "10.0.2.10", 5432, "allow", "Internal network to database on PostgreSQL port"),
        ("10.1.2.3", "10.0.2.10", 5432, "allow", "Single app host to database"),
        ("0.0.0.0/0", "10.0.1.5", 3389, "allow", "Remote desktop open to the whole internet"),
        ("192.168.1.0/24", "192.168.1.10", 80, "allow", "Internal subnet to internal web service"),
        ("0.0.0.0/0", "10.0.1.5", 22, "deny", "Deny SSH from the internet (explicit deny)"),
        ("10.0.0.0/8", "0.0.0.0/0", 443, "allow", "Internal hosts to the internet on HTTPS"),
        ("203.0.113.10", "10.0.1.5", 443, "allow", "Partner address to web server on HTTPS"),
    ]
    for i, (src, dst, port, action, desc) in enumerate(anchors, start=1):
        sev = severity_for(src, dst, port, action)
        rules.append({
            "id": f"RULE-{i:03d}",
            "source": src, "dest": dst, "port": port,
            "protocol": "TCP" if port != 53 else "UDP",
            "action": action,
            "description": desc,
            "label": "risky" if sev in ("high", "medium") else "safe",
            "severity": sev,
        })
    # Fill to 60 with deterministic random combinations.
    i = len(rules) + 1
    while len(rules) < 60:
        src, _ = random.choice(SOURCES)
        dst, _ = random.choice(DESTS)
        port = random.choice(COMMON_PORTS)
        action = random.choice(["allow", "allow", "allow", "deny"])
        desc = f"{action.capitalize()} TCP port {port} from {src} to {dst}"
        sev = severity_for(src, dst, port, action)
        rules.append({
            "id": f"RULE-{i:03d}",
            "source": src, "dest": dst, "port": port,
            "protocol": "TCP",
            "action": action,
            "description": desc,
            "label": "risky" if sev in ("high", "medium") else "safe",
            "severity": sev,
        })
        i += 1
    return rules


def make_lora_dataset():
    """300 synthetic rule descriptions, labelled risky/safe by the same
    logic as the audit rules. Templates are varied so the classifier
    must learn the pattern, not memorise one sentence."""
    rng = random.Random(123)
    examples = []
    risky_templates = [
        "Allow SSH port 22 from {src} to {dst}",
        "Allow remote desktop port 3389 from {src} to {dst}",
        "Allow PostgreSQL port 5432 from {src} to {dst}",
        "Allow MySQL port 3306 from {src} to {dst}",
        "Allow Redis port 6379 from {src} to {dst}",
        "Allow MongoDB port 27017 from {src} to {dst}",
        "Allow any source to any destination on any port",
        "Allow all traffic from {src} to {dst}",
        "Open port {port} to the whole internet for {dst}",
        "Allow database access from the internet to {dst}",
    ]
    safe_templates = [
        "Allow SSH port 22 from a single operator host {src} to {dst}",
        "Allow HTTPS port 443 from {src} to a public web server {dst}",
        "Allow PostgreSQL port 5432 from a single app host {src} to {dst}",
        "Deny SSH port 22 from the internet to {dst}",
        "Deny remote desktop port 3389 from {src} to {dst}",
        "Allow HTTP port 80 from an internal subnet {src} to {dst}",
        "Allow DNS port 53 from {src} to a named resolver {dst}",
        "Deny all traffic from {src} to {dst}",
        "Allow HTTPS from an internal network {src} to {dst}",
    ]
    risky_sources = ["0.0.0.0/0", "the whole internet", "anywhere", "0.0.0.0/0"]
    safe_sources = ["10.1.2.3", "10.0.0.0/8", "192.168.1.0/24", "a single trusted host", "203.0.113.10"]
    dests = ["10.0.1.5", "10.0.2.10", "192.168.1.10", "the database server", "the web server"]
    for _ in range(150):
        t = rng.choice(risky_templates)
        src = rng.choice(risky_sources)
        dst = rng.choice(dests)
        port = rng.choice([22, 3389, 5432, 3306, 6379, 27017])
        text = t.format(src=src, dst=dst, port=port)
        examples.append({"text": text, "label": "risky"})
    for _ in range(150):
        t = rng.choice(safe_templates)
        src = rng.choice(safe_sources)
        dst = rng.choice(dests)
        text = t.format(src=src, dst=dst)
        examples.append({"text": text, "label": "safe"})
    rng.shuffle(examples)
    return examples


def main():
    GUIDANCE.mkdir(parents=True, exist_ok=True)
    for doc_id, (title, body) in GUIDANCE_DOCS.items():
        # Bodies are adjacent string literals in source; collapse them
        # to clean single-paragraph text with no stray quote characters.
        clean = " ".join(body.replace('"', "").split())
        (GUIDANCE / f"{doc_id}.md").write_text(f"# {title}\n\n{clean}\n", encoding="utf-8")
    rules = make_rules()
    (DATA / "rules.json").write_text(json.dumps(rules, indent=2) + "\n", encoding="utf-8")
    examples = make_lora_dataset()
    # Stratified split: 240 train / 60 test, balanced.
    risky = [e for e in examples if e["label"] == "risky"]
    safe = [e for e in examples if e["label"] == "safe"]
    train = risky[:120] + safe[:120]
    test = risky[120:] + safe[120:]
    random.Random(7).shuffle(train)
    random.Random(7).shuffle(test)
    (DATA / "lora_dataset.jsonl").write_text("".join(json.dumps(e) + "\n" for e in examples), encoding="utf-8")
    (DATA / "lora_train.jsonl").write_text("".join(json.dumps(e) + "\n" for e in train), encoding="utf-8")
    (DATA / "lora_test.jsonl").write_text("".join(json.dumps(e) + "\n" for e in test), encoding="utf-8")
    print(f"guidance docs: {len(GUIDANCE_DOCS)}")
    print(f"rules: {len(rules)} risky={sum(1 for r in rules if r['label']=='risky')} safe={sum(1 for r in rules if r['label']=='safe')}")
    print(f"lora train: {len(train)} test: {len(test)}")


if __name__ == "__main__":
    main()
