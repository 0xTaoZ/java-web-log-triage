# Detection Rules

These rules are intentionally simple so the project stays easy to read and
modify while learning Java.

## Path traversal probe

Flags request paths containing `../` or encoded `%2e%2e` segments.

Example:

```text
GET /../../etc/passwd HTTP/1.1
```

## Web shell probe

Flags PHP paths that mention upload, cmd, or shell.

Example:

```text
GET /uploads/cmd.php HTTP/1.1
```

## Admin login probe

Flags request paths containing `/admin` or `/login`.

Example:

```text
GET /admin/login.php HTTP/1.1
```

## WordPress probe

Flags common WordPress endpoints such as `wp-login.php`, `xmlrpc.php`, and
`/wp-admin`.

## Client error sources

Counts `4xx` responses by source IP. This is not a detection by itself, but it
helps spot clients that are repeatedly probing missing, blocked, or invalid
paths during a small lab review.

## Server error sources

Counts `5xx` responses by source IP. This can point to clients triggering
backend errors or to routes that need reliability review during a lab incident
walkthrough.

## Method/status pairs

Counts combinations such as `GET 404` or `POST 502`. This gives a small
review hint about which HTTP methods are producing failures without needing a
full query language.

## Scanner user agents

Flags simple scanner or automation user agents such as `sqlmap`, `nikto`,
`curl/`, and `python-requests`. This is a small lab-friendly signal, not a
complete bot detector, because many normal tools can also send custom user
agents.
