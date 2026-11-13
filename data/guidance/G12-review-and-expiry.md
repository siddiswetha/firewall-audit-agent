# Review dates and expiry

Firewall rules age badly. A rule that was correct for a migration or a test can linger for years after the work is done. Give every temporary rule an expiry date and every permanent rule a review date. At review, check that the service still exists, that the source is still correct, and that the port is still needed. Removing a stale rule is usually safer than leaving it in place.
