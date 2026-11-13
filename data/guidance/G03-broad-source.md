# Overly broad sources

A source of 0.0.0.0/0 means anyone on the internet can try to reach the destination. That is sometimes correct for a public web service on ports 80 or 443, but it is rarely correct for internal services, databases, or admin ports. Prefer a named network, a partner address range, or a single host. When a broad source is unavoidable, pair it with a narrow destination and port, and add logging and alerting so abuse is visible quickly.
