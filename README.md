# C2-JA4-Fingerprints

A list of JA4+ fingerprints (JA4 client TLS, JA4S server TLS, and JA4H HTTP) for the SSL/TLS and HTTP implementations used by various Command-and-Control (C2) and red team frameworks. The goal is to help blue teams with the appropriate network visibility gather additional indicators for identifying C2 activity, and to help red teamers understand how their infrastructure can be fingerprinted.

This is the JA4 counterpart to Cedric Owens' [cedowens/C2-JARM](https://github.com/cedowens/C2-JARM), which catalogs JARM hashes for many of the same tools.

JA4 fingerprints are more resilient than legacy JA3/JARM hashes: they are human-readable, broken into meaningful sections, and remain stable across TLS implementations rather than per-connection randomization. For more on the JA4+ suite, see FoxIO's work: https://github.com/FoxIO-LLC/ja4

These fingerprints alone are not sufficient to detect C2 in a high-fidelity manner, but combined with other high-value indicators they are a useful signal. They also highlight the need for red teams to ensure their C2 infrastructure is not exposed for public access.

Every signature listed is either the implant's own traffic (JA4 client TLS, JA4H HTTP) or the C2 server's response (JA4S server TLS). Operator-tool probe fingerprints from curl, openssl, and similar are intentionally excluded. Fingerprints were collected in isolated lab environments. The `commit` column records the upstream commit of each tool that was tested. Server-side fingerprints in particular may shift with different certificates, public domains, reverse proxies, or non-default profiles. The machine-readable version lives in [`c2-ja4-fingerprints.csv`](c2-ja4-fingerprints.csv).

## Fingerprint types

- JA4 - client TLS ClientHello fingerprint
- JA4S - server TLS ServerHello fingerprint
- JA4H - HTTP client request fingerprint

## Fingerprints

| Tool | Type | Protocol | JA4 Signature | Link | Commit |
|---|---|---|---|---|---|
| AdaptixC2 | JA4 | HTTPS API | `t13i3111h2_e8f1e7e78f70_b26ce05bbdd6` | https://github.com/Adaptix-Framework/AdaptixC2 | `a4b80bf370f7` |
| AtlasC2 | JA4H | HTTP plaintext | `ge11nn020000_609437d8192d_000000000000_000000000000` | https://github.com/Gr1mmie/AtlasC2 | `98eb7d294f0d` |
| AtlasC2 | JA4H | HTTP plaintext | `ge11nn030000_86ab2bdf2091_000000000000_000000000000` | https://github.com/Gr1mmie/AtlasC2 | `98eb7d294f0d` |
| CALDERA | JA4H | HTTP plaintext | `po11nn040000_b9c176b8216c_000000000000_000000000000` | https://github.com/mitre/caldera | `3735d9eb0868` |
| Covenant | JA4 | HTTPS admin UI/API | `t13i3111h2_e8f1e7e78f70_b26ce05bbdd6` | https://github.com/cobbr/Covenant | `5decc3ccfab0` |
| Covenant | JA4 | HTTPS listener probe | `t13i3111h2_e8f1e7e78f70_b26ce05bbdd6` | https://github.com/cobbr/Covenant | `5decc3ccfab0` |
| Havoc | JA4 | HTTPS | `t13i1012h2_01be160bb49b_e24568c0d440` | https://github.com/HavocFramework/Havoc | `c84f7755a8b1` |
| Havoc | JA4H | HTTP plaintext | `po11nn070000_517823f2c371_000000000000_000000000000` | https://github.com/HavocFramework/Havoc | `c84f7755a8b1` |
| Havoc | JA4H | HTTP plaintext malleable profile | `po11nr110000_757db81c297b_000000000000_000000000000` | https://github.com/HavocFramework/Havoc | `c84f7755a8b1` |
| Havoc | JA4S | HTTPS | `t130200_1301_a56c5b993250` | https://github.com/HavocFramework/Havoc | `c84f7755a8b1` |
| Realm | JA4 | gRPC over TLS / HTTP2 | `t13i1010h2_61a7ad8aa9b6_3fcd1a44f3e3` | https://github.com/spellshift/realm | `c8ff867ead30` |
| Realm | JA4 | HTTP/1.1 over TLS | `t13i101000_61a7ad8aa9b6_dc02626b439c` | https://github.com/spellshift/realm | `c8ff867ead30` |
| Realm | JA4 | QUIC | `u13d0312rc_55b375c5d22e_834386177a8c` | https://github.com/spellshift/realm | `c8ff867ead30` |
| Realm | JA4H | HTTP/1.1 plaintext | `po11nn040000_ea8d9d1bb0cb_000000000000_000000000000` | https://github.com/spellshift/realm | `c8ff867ead30` |
| Realm | JA4S | gRPC over TLS / HTTP2 | `t130200_1301_a56c5b993250` | https://github.com/spellshift/realm | `c8ff867ead30` |
| Realm | JA4S | HTTP/1.1 over TLS | `t130200_1301_a56c5b993250` | https://github.com/spellshift/realm | `c8ff867ead30` |
| SharpC2 | JA4S | HTTPS handler probe | `t130200_1302_a56c5b993250` | https://github.com/rasta-mouse/SharpC2 | `dd118fb36ff6` |
| SharpC2 | JA4S | HTTPS teamserver API | `t130200_1302_a56c5b993250` | https://github.com/rasta-mouse/SharpC2 | `dd118fb36ff6` |
| Sliver | JA4 | HTTPS C2 | `t13i131000_f57a46bbacb6_e5728521abd4` | https://github.com/BishopFox/sliver | `3bbaf805104d` |
| Sliver | JA4 | mutual TLS | `t13i131000_f57a46bbacb6_e5728521abd4` | https://github.com/BishopFox/sliver | `3bbaf805104d` |
| Sliver | JA4 | mutual TLS beacon | `t13i131000_f57a46bbacb6_e5728521abd4` | https://github.com/BishopFox/sliver | `3bbaf805104d` |
| Sliver | JA4H | HTTP C2 plaintext | `ge11cn040000_6d5a62ca5b6a_94a2776e7bd6_18cb85ae66cf` | https://github.com/BishopFox/sliver | `3bbaf805104d` |
| Sliver | JA4H | HTTP C2 plaintext | `po11cn050000_bb52516416a2_94a2776e7bd6_18cb85ae66cf` | https://github.com/BishopFox/sliver | `3bbaf805104d` |
| Sliver | JA4H | HTTP C2 plaintext | `po11nn050000_bb52516416a2_000000000000_000000000000` | https://github.com/BishopFox/sliver | `3bbaf805104d` |
| Sliver | JA4S | HTTPS C2 | `t130200_1301_a56c5b993250` | https://github.com/BishopFox/sliver | `3bbaf805104d` |
| Sliver | JA4S | mutual TLS | `t130200_1301_a56c5b993250` | https://github.com/BishopFox/sliver | `3bbaf805104d` |
| Sliver | JA4S | mutual TLS beacon | `t130200_1301_a56c5b993250` | https://github.com/BishopFox/sliver | `3bbaf805104d` |

## Contributing

Contributions welcome! Please include the tool, the JA4 type, the protocol/transport tested, the fingerprint value, a link to the tool, and the tested upstream commit.
