# AGENTS.md

## Project

Android Local Firewall.

The application creates a local Android VPN using VpnService and uses it
as a firewall.

This is NOT a remote VPN service.

There is no VPN server and no backend server.

All firewall processing must happen locally on the Android device.

---

## Primary goals

1. Build a stable Android VpnService.
2. Intercept network traffic using a TUN interface.
3. Allow or block traffic based on firewall rules.
4. Support per-application firewall rules.
5. Support IP, CIDR, port, TCP and UDP rules.
6. Store rules locally.
7. Store traffic logs locally.

---

## Technology

Use:

- Kotlin
- Jetpack Compose
- Android VpnService
- Android Architecture Components
- Room
- Coroutines
- Gradle Kotlin DSL

Prefer standard Android APIs.

Avoid unnecessary dependencies.

---

## Security rules

Never:

- Upload network traffic
- Upload DNS history
- Upload browsing history
- Create a remote VPN server
- Add analytics without explicit approval
- Add advertising SDKs
- Disable TLS validation
- Implement custom cryptography
- Store sensitive packet content unless explicitly required

---

## Networking rules

VpnService must be used.

Allowed connections must not accidentally bypass firewall policy.

Never use `VpnService.Builder.addDisallowedApplication()` as a firewall
BLOCK rule. Disallowed applications bypass the VPN and use the underlying
system network.

Do not call `VpnService.Builder.allowBypass()`.

Sockets created by the VPN implementation that connect to the Internet
must use VpnService.protect() when appropriate to prevent routing loops.

Do not implement a complete TCP/IP stack from scratch unless there is
a documented technical reason.

Prefer mature and well-tested networking components.

---

## Development rules

For every change:

1. Understand the existing architecture.
2. Make the smallest reasonable change.
3. Add or update tests for behavioral production-code changes where appropriate.
4. Keep production call sites, unit tests, instrumentation tests, test helpers,
   mocks/fakes, and fixtures consistent with production APIs.
5. Run unit tests.
6. Run Android lint.
7. Build the application.
8. Do not merge or report a task as complete if the code does not compile or any
   required test, lint, or build command fails.

Whenever changing a production API, perform a repository-wide search for every
usage before considering the change complete. Production APIs include function
signatures, constructor parameters, callback parameters, interfaces, data
classes, public or internal methods, and helper functions used by tests.

Explicitly check and update all affected:

- production call sites
- unit tests
- instrumentation tests
- test helpers
- mocks and fakes
- fixtures

When adding, removing, or reordering parameters, never assume existing callers
still compile. Search for every call site and update all callers in the same
change. If a production-code change causes test compilation errors, the
implementation is incomplete; do not treat the failure as merely a test
problem.

In Kotlin tests, prefer named arguments for functions or constructors with
multiple callback or function parameters, especially when parameters have
similar function types. This reduces accidental argument binding after API
changes.

Before finishing any implementation or pull request, run all of these commands:

```bash
./gradlew test
./gradlew lint
./gradlew assembleDebug
```

Do not report the task as complete if any command fails. Before finalizing a
pull request, perform this consistency check:

```text
production API changed?
    ↓
search all usages
    ↓
update production callers
    ↓
update tests/test helpers
    ↓
run test
    ↓
run lint
    ↓
build APK
```

---

## Code style

Prefer:

- small classes
- clear names
- immutable data where practical
- dependency injection through constructors
- testable business logic
- separation between UI and firewall engine

Avoid:

- giant Activity classes
- giant VpnService classes
- global mutable state
- hard-coded firewall rules

---

## Architecture

Keep these areas separate:

ui/
vpn/
firewall/
network/
data/

The VpnService should not contain UI logic.

The firewall rule engine should be testable without Android UI.

---

## Agent behavior

When implementing a GitHub issue:

1. Read README.md
2. Read REQUIREMENTS.md
3. Read ARCHITECTURE.md
4. Read this AGENTS.md
5. Implement only the requested scope
6. Add tests
7. Build the project
8. Fix build/test failures
9. Summarize changes in the pull request

If requirements are unclear, prefer the safest and simplest implementation.
