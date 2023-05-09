# TLS Core
A toy implementation of the TLS v1.3 protocol, with a focus on code readability and correctness. Not for production due to lack of security and performance concerns.

## v0.1 milestone
Successfully negotiate a TLS handshake, then send an HTTPS request to `https://api.github.com/octocat`:

```
>>> GET /octocat HTTP/1.1
>>> HOST: api.github.com
>>> Connection: close
>>> user-agent: rust
>>> accept: */*

<<<HTTP/1.1 200 OK
<<<Server: GitHub.com
<<<Date: Wed, 28 Jun 2023 05:43:10 GMT
<<<Content-Type: application/octocat-stream
<<<Content-Length: 873
<<<x-github-api-version-selected: 2022-11-28
<<<Access-Control-Expose-Headers: ETag, Link, Location, Retry-After, X-GitHub-OTP, X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Used, X-RateLimit-Resource, X-RateLimit-Reset, X-OAuth-Scopes, X-Accepted-OAuth-Scopes, X-Poll-Interval, X-GitHub-Media-Type, X-GitHub-SSO, X-GitHub-Request-Id, Deprecation, Sunset
<<<Access-Control-Allow-Origin: *
<<<Strict-Transport-Security: max-age=31536000; includeSubdomains; preload
<<<X-Frame-Options: deny
<<<X-Content-Type-Options: nosniff
<<<X-XSS-Protection: 0
<<<Referrer-Policy: origin-when-cross-origin, strict-origin-when-cross-origin
<<<Content-Security-Policy: default-src 'none'
<<<Vary: Accept-Encoding, Accept, X-Requested-With
<<<X-RateLimit-Limit: 60
<<<X-RateLimit-Remaining: 52
<<<X-RateLimit-Reset: 1687934194
<<<X-RateLimit-Resource: core
<<<X-RateLimit-Used: 8
<<<Accept-Ranges: bytes
<<<X-GitHub-Request-Id: E389:9566:13117A:27123C:649BC876
<<<connection: close
<<<
<<<
<<<               MMM.           .MMM
<<<               MMMMMMMMMMMMMMMMMMM
<<<               MMMMMMMMMMMMMMMMMMM      ____________________________
<<<              MMMMMMMMMMMMMMMMMMMMM    |                            |
<<<             MMMMMMMMMMMMMMMMMMMMMMM   | Practicality beats purity. |
<<<            MMMMMMMMMMMMMMMMMMMMMMMM   |_   ________________________|
<<<            MMMM::- -:::::::- -::MMMM    |/
<<<             MM~:~ 00~:::::~ 00~:~MM
<<<        .. MMMMM::.00:::+:::.00::MMMMM ..
<<<              .MM::::: ._. :::::MM.
<<<                 MMMM;:::::;MMMM
<<<          -MM        MMMMMMM
<<<          ^  M+     MMMMMMMMM
<<<              MMMMMMM MM MM MM
<<<                   MM MM MM MM
<<<                   MM MM MM MM
<<<                .~~MM~MM~MM~MM~~.
<<<             ~~~~MM:~MM~~~MM~:MM~~~~
<<<            ~~~~~~==~==~~~==~==~~~~~~
<<<             ~~~~~~==~==~==~==~~~~~~
<<<                 :~==~==~==~==~~
```