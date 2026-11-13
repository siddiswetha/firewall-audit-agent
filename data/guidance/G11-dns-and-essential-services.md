# Essential services need care too

Some services, such as DNS on port 53, are easy to overlook because they are always needed. Allow DNS only to named resolvers, and do not allow a host to use any external resolver without a reason. The same care applies to other always-on services: allow the exact port and protocol, to the exact destination, and log unusual volumes that could indicate misuse.
