# Security policy

## Supported versions

Android Local Firewall is still under development and has not published a
stable release. Security fixes are applied to the latest revision on the
`main` branch.

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's
**Security** tab by selecting **Report a vulnerability**. Do not open a public
issue containing vulnerability details, traffic captures, browsing history,
DNS history, credentials, or other sensitive data.

Include the affected revision, Android version, reproduction steps, and the
security impact when that information can be shared safely. You should receive
an acknowledgement within seven days. Once a report is confirmed, remediation
and coordinated disclosure timing will be discussed with the reporter.

## Scope

Reports involving local VPN routing, firewall-policy bypasses, traffic or DNS
data exposure, insecure local storage, and unintended network communication
are especially relevant. This project has no remote VPN or backend service and
must not transmit telemetry or captured traffic.
