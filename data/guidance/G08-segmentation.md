# Network segmentation

Split a network into segments so that a problem in one segment does not automatically spread to the others. Keep databases in a segment that only application servers can reach, keep admin interfaces in a segment that only operators can reach, and keep user devices separate from servers. Firewall rules between segments should be explicit and narrow. Segmentation is a practical form of least privilege applied to the network layout itself.
