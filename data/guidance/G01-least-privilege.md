# Least privilege for firewall rules

A firewall rule should allow only the traffic a service actually needs, and nothing more. Start from what the application requires: the exact source, the exact destination, the exact port and protocol. If a rule allows a whole network when one host would do, or a range of ports when one port would do, tighten it. Review broad rules on a schedule and remove rules that no longer have an owner or a business need. Least privilege is not a one-time setting; it is a habit of asking, for every allow rule, whether a narrower rule would still work.
