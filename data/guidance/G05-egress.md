# Control outbound traffic too

Firewalls are often tuned only for inbound traffic, but outbound rules matter as well. A host that is compromised will often try to contact an external server, so allowing all outbound traffic makes that harder to spot. Allow outbound traffic only to the destinations and ports a service needs, such as a named update server or a specific API endpoint. Log outbound connections that are denied and review them; a sudden rise in denied outbound attempts can be an early sign of a problem.
