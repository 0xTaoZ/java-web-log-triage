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

