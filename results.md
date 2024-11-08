# Results

## Fresh Look at results

### nginx

- 48B vs 80B STEK behaves same
- content is decided on by Host header
- Single server with multiple vHosts:
    - resumes all tickets
    - it does not matter if each vHost has a different STEK
        - *bug*
    - it matters whether vHosts use same port
        - when using different ports, tickets are not resumed
- configuring a default host that errors on
    - does not make a difference in single server setting
    - HTTP (404)
        - actually causes more tickets to be resumed, as this vhost "bridges the gap" between the ports and even servers
        - as there is a fallback with the same cert as on the initial (I assume the ticket is always bound to the default host cert), the ticket is resumed. Only afterwards the host header is looked at, but can diverge from the SNI
        - only 404s for unknown Host headers
        - means: in a two port/server setting a ticket can be resumed for b.com, which was previously not possible due to different cert
    - TLS (alert)
        - does not affect single server (single port) scenario
        - causes connections with an unknown SNI to be completely rejected
        - still only cares about the SNI, SNI and Host may diverge, unknown Host headers result in HTTP error

### apache

- detects SNI!=Host header and returns HTTP 421
- does not resume ticket if SNI mismatch
- no SNI
    - resumes if ticket issuer==a
    - normal
        - body determined by host header
            - in 1.2 checks that host header matches the ticket issuer if ticket was resumed
                - i.e. ticket "locks" sni to default - then it must match (else 421)
            - in 1.3 host header can diverge
            - if no resumption, host can be anything
    - strict
        - in 1.3 body is always a 403
        - in 1.2:
            - if resumed (i.e. ticket from a) and host=a: a.com
            - if resumed (i.e. ticket from a) and host!=a: 421
            - 403 otherwise


### OLS

- resumes tickets if SNI matches
- body determined by host header (mismatch is accepted)
- only case where "unintended" resumption worked was between multiple admin interfaces
    - we can assume if two admin interfaces share a STEK that they are on the same trust level




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

## DONE

Es gibt bei Apache eine Option SSLStrictSNIVHostCheck On
Wenn man dann die SNI weglässt kriegt man HTTP 403 You don't have permission to access this resource.Reason: The client software did not provide a hostname using Server Name Indication (SNI), which is required to access this server.

Willst du das vllt noch mit aufnehmen? 

---

- Evaluate same cert on both servers
- OLS admin interface

