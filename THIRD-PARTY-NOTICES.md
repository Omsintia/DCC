# Third-Party Notices

DnsCryptControl bundles and builds on third-party software. This file reproduces
the required copyright and license notices for everything it **redistributes**
(ships in the installer or compiles into the shipped binaries), and acknowledges
the development-only tooling it does not ship.

DnsCryptControl itself is licensed under the ISC License — see [LICENSE](LICENSE).

---

## Redistributed components

### dnscrypt-proxy (bundled binary)

The installer ships the official `dnscrypt-proxy` Windows binary (v2.1.16) into
`%ProgramData%\DnsCryptControl`. DnsCryptControl is a GUI front-end for it.

Project: <https://github.com/DNSCrypt/dnscrypt-proxy>

```
ISC License

Copyright (c) 2018-2026, Frank Denis <j at pureftpd dot org>

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
```

### DNSCrypt public resolver lists (bundled data)

The installer bundles minisign-signed copies of the DNSCrypt resolver lists
(`public-resolvers.md`, `odoh-servers.md`, `odoh-relays.md`) so the app has a
verified default resolver on a fresh install and adding ODoH never leaves DNS
without a source. These lists are the same data `dnscrypt-proxy` itself fetches
and caches at runtime.

Source: <https://github.com/DNSCrypt/dnscrypt-resolvers> — maintained by
Frank Denis (DNSCrypt project). The upstream list files carry the header
"This list is maintained by Frank Denis" and are distributed for consumption by
dnscrypt-proxy clients; the repository does not state a formal software license.
The bundled copies are byte-for-byte the signed upstream data and are verified
against the DNSCrypt project's minisign public key before use.

### Bundled NuGet libraries (compiled into the shipped binaries)

The signed UI and helper executables link the following packages. Their runtime
DLLs are installed alongside the executables.

| Package | Version | License |
| --- | --- | --- |
| WPF-UI | 4.3.0 | MIT |
| CommunityToolkit.Mvvm | 8.4.2 | MIT |
| BouncyCastle.Cryptography | 2.6.2 | MIT |
| Tomlyn | 2.3.2 | BSD-2-Clause |
| Microsoft.Extensions.Hosting | 8.0.1 | MIT |
| Microsoft.Extensions.Hosting.WindowsServices | 8.0.1 | MIT |
| System.ServiceProcess.ServiceController | 8.0.1 | MIT |
| System.IO.Pipes.AccessControl | 5.0.0 | MIT |
| Microsoft.Management.Infrastructure | 3.0.0 | MIT |

Copyright notices:

- WPF-UI — Copyright (c) 2021-2025 Leszek Pomianowski and WPF UI Contributors
- CommunityToolkit.Mvvm — Copyright (c) .NET Foundation and Contributors
- BouncyCastle.Cryptography — Copyright (c) 2000-2025 The Legion of the Bouncy Castle Inc. (https://www.bouncycastle.org)
- Tomlyn — Copyright (c) 2019-2026 Alexandre Mutel
- Microsoft.Extensions.* / System.ServiceProcess.ServiceController / System.IO.Pipes.AccessControl — Copyright (c) .NET Foundation and Contributors
- Microsoft.Management.Infrastructure — Copyright (c) Microsoft Corporation

#### MIT License

Applies to every MIT package listed above.

```
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

#### BSD 2-Clause License (Tomlyn)

```
Copyright (c) 2019-2026, Alexandre Mutel
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

---

## Development-only tooling (not redistributed)

These are used to build, test, fuzz, or benchmark DnsCryptControl. They are
**not** shipped in the installer and are **not** compiled into the released
binaries; they are listed here for completeness.

| Tool | Purpose | License |
| --- | --- | --- |
| xUnit | unit tests | Apache-2.0 |
| CsCheck | property-based fuzzing | Apache-2.0 |
| WiX Toolset | MSI packaging | MS-RL |
