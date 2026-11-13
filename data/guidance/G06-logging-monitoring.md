# Logging and monitoring

A rule without logging is hard to audit and hard to defend. Log allowed and denied connections for sensitive services, keep the logs long enough to investigate incidents, and monitor them rather than collecting them unread. Alert on repeated denied attempts, on first use of a rarely used rule, and on changes to the rule set itself. When a finding is raised, the log should be able to show whether the rule was actually used, by whom, and how often.
