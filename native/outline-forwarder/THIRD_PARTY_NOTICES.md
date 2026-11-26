# Third-Party Notices — `liboutline_forwarder.so`

This document inventories the exact compiled module graph linked into `liboutline_forwarder.so`
(verified via `go version -m liboutline_forwarder.so` and `native/outline-forwarder/go.sum` from
the single upstream pin `native/outline-forwarder/OUTLINE_SDK_COMMIT`:
`ff3fcd3bf7571967a6e2fa324e93f242505f514a`).

## Compiled Dependency Inventory

| Component | Module / Source | Pinned Version / Revision | Go Module Checksum | License |
|---|---|---|---|---|
| **Outline SDK (`network/lwip2transport`, `network/packetrelay`, `transport`)** | `golang.getoutline.org/sdk` (`https://github.com/OutlineFoundation/outline-sdk`) | `v0.1.1-0.20261110205933-ff3fcd3bf757` (`ff3fcd3bf7571967a6e2fa324e93f242505f514a`) | `h1:94QVqUhUqnxyOu2tdmU597tNBODQ81abccIAsNTz2x8=` | Apache-2.0 |
| **go-tun2socks (`core` CGo wrapper)** | `github.com/eycorsican/go-tun2socks` | `v1.16.11` | `h1:+hJDNgisrYaGEqoSxhdikMgMJ4Ilfwm/IZDrWRrbaH8=` | MIT |
| **lwIP TCP/IP stack (embedded in `go-tun2socks/core/c`)** | Swedish Institute of Computer Science (SICS) lwIP | Bundled in `github.com/eycorsican/go-tun2socks@v1.16.11` | Included in `go-tun2socks` module sum above | BSD-3-Clause |
| **Go Extended Unix Syscalls (`golang.org/x/sys/unix`)** | `golang.org/x/sys` | `v0.35.0` | `h1:vz1N37gP5bs89s7He8XuIYXpyY0+QlsKmzipCbUtyxI=` | BSD-3-Clause |
| **Go Standard Library & Runtime** | `go` toolchain | `go1.25.0` | Official Go distribution | BSD-3-Clause |

No GPL, AGPL, or LGPL code (including NetGuard) is linked, copied, or derived.

---

## 1. Outline SDK (`golang.getoutline.org/sdk`) — Apache License 2.0

Copyright The Outline Authors.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
compliance with the License. You may obtain a copy of the License at:

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing permissions and limitations under the
License.

---

## 2. `github.com/eycorsican/go-tun2socks` — MIT License

```text
MIT License

Copyright (c) 2018 eycorsican

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

---

## 3. lwIP TCP/IP Stack — BSD 3-Clause License

```text
Copyright (c) 2001-2004 Swedish Institute of Computer Science.
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
3. The name of the author may not be used to endorse or promote products
   derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
OF SUCH DAMAGE.
```

---

## 4. Go Standard Library & Runtime — BSD 3-Clause License

Copyright 2009 The Go Authors. All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted
under the Go 3-Clause BSD license (https://go.dev/LICENSE).
