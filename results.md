# Results

## Ticket Resumption

- nginx
    - no difference between 48B and 80B STEK
    - `one-server` and `one-server-different-steks` behave the same
    - resumed all tickets
    - body determined by host header value
    - (if no resumption) cert determined by SNI, body still by host header
- apache
    - `one-server` and `one-server-different-steks` behave the same
    - detects mismatch of SNI and `Host` header and returns `421 Misdirected Request`
    - if SNI is omitted, tickets from first domain can be resumed
        - in TLS 1.2 a `Host` header specifying a different than the first host returns `421 Misdirected Request`
        - in TLS 1.3 the content is determined by the `Host` header
- OLS
    - does not support `one-server-different-steks`
    - resumes tickets if SNI matches (no SNI does not resume tickets)
    - body determined by host header value
    - 404s for unknown domains (as we did not specify a wildcard in listener for a fallback)

## Distinct STEKs per vHost

- nginx
    - STEK is configured per vHost
    - global setting is used as default per vHost
    - due to bug only uses STEK of default vHost
- apache
    - STEK can be configured per vHost
    - global setting exists to **TODO look into how it is used**
    - fallback (no SNI): first host (**TODO does something like `default_host` exist?**)
- openlitespeed
    - only allows one STEK per running server (neither listeners nor vHosts can use a different stek)
