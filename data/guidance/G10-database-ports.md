# Protect database ports

Database ports such as 5432 for PostgreSQL, 3306 for MySQL, 1433 for SQL Server, 6379 for Redis, and 27017 for MongoDB should never be reachable from the internet. They should be reachable only from the specific application hosts that need them, on the specific network segment where the database lives. If a database port is exposed broadly, treat it as high risk: check whether data was accessed, narrow the source immediately, and add authentication and logging checks.
