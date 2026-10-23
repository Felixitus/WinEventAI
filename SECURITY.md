# Security

WinEventAI reads security-relevant data - event logs including the Security
channel, logon times, account names. This file says what the tool protects,
what it does not, and how to report a problem.

## Reporting a vulnerability

Please report security problems privately: in this repository under
**Security → Report a vulnerability**. If that button is not offered, open an
issue that only asks for a private contact - without details of the problem.
Include the version (`wineventai --version`), what you did and what happened.

## What the tool guarantees

| Property | How it is enforced |
|---|---|
| Read-only | No command changes the system. Fixes are only shown as suggestions. The probes only read (WMI, registry) and send queries (ping, DNS, SNTP) inside the local network. |
| No cloud call | The language model is only called on `localhost`. Another address, or a model that Ollama forwards to a cloud service (`*:cloud`, `remote_host`), is refused unless `ai.allow_cloud: true` is set in the configuration. The check runs at the status query and again before every call. |
| No internet traffic of its own | Probes skip every address outside the private ranges (network, DNS, time). There is no update check and no telemetry. |
| Data minimisation towards the model | Bundles are pseudonymised (user, host, SID, IP, MAC, domain); the mapping table stays local. Model statements are checked against the input; uncovered ones are rejected. |
| Private data folder | Configuration, rules, knowledge base and runs live in `%LOCALAPPDATA%\WinEventAI`, readable only by the user (plus SYSTEM and administrators). |
| Report without external resources | The HTML report loads nothing from the network; event texts are HTML-escaped. |
| Visible PowerShell | Scripts are started with `-File`, never with `-EncodedCommand`. |

## Fixed in 2.3.0: shared data folder

Up to 2.2.0 the data folder was `C:\ProgramData\WinEventAI`. Below ProgramData
every local user may create files and read everything. A normal user could
therefore have planted a configuration (e.g. `allow_cloud` plus a foreign
address) or a rule file that an administrator's next run would have loaded,
and every user could read the reports. Since 2.3.0 the data folder is per
user. The old folder is no longer read; the tool points it out once so that
it can be deleted.

## What the tool does not protect against

- **An administrator or SYSTEM** can read and change everything in the user
  profile, including the runs. That is the Windows trust model.
- **The evidence ZIP is not pseudonymised** on purpose - it is evidence.
  Hand it on only where the raw logs may go.
- **Unsigned executables.** The release is not code-signed. Check the
  published SHA-256 before running it.
- **`ai.allow_cloud: true`** sends pseudonymised findings to the configured
  service. That is a deliberate decision of whoever writes it into the
  configuration.
