# Any-to-any rules

A rule that allows any source to any destination on any port defeats the purpose of a firewall. It hides the real traffic pattern, makes audits meaningless, and lets a single compromised host reach everything. Replace any-to-any rules with specific rules for each service, or at least split them by destination and port. If an any-to-any rule exists temporarily for troubleshooting, give it an expiry date, an owner, and a review date, and remove it promptly.
