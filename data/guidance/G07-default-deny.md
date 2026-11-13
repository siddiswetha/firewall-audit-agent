# Default deny

The safest starting position is to deny traffic by default and allow only what is explicitly needed. With default deny, a missing rule fails closed: traffic is blocked until someone reviews it and adds a deliberate allow rule. With default allow, a missing rule fails open and traffic flows unchecked. Document the default policy, make it visible to reviewers, and treat any exception to it as a decision that needs a reason and an owner.
