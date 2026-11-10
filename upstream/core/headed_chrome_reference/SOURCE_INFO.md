# Headed Chrome registration source

- Reference repository: `E:\\pc_ios\\gpt-outlook-register-registration-complete-20260822\\gpt-outlook-register-registration`
- Reference commit: `31e59ee45a63cda259d10fefd297995e6aa84f3b`
- Source path: `registration_core/app.py`
- Git blob: `23a3622ef73d0bcb16788e90fd8cafb5875b6cd6`
- Canonical LF SHA-256: `a0ee9bb2a4216eb11b8ce4ef9066f1e361f32434d5d9db220d7e1174a2f6bfac`
- Reference adapter path: `webui/browser_registration.py`
- Reference adapter Git blob: `25ff24b97eedbf51cb6d5a055c4fcc9f0d4e1520`
- Reference adapter SHA-256: `7b49c2cd3b20bfd4120fd8387c65875589926f09ea4a9bf4a6a640462f694a42`

`vendor/app.py` starts from the Git blob above and includes the explicitly listed
local fix below. The reference commit/blob/hash remain the upstream identity;
`VENDORED_CANONICAL_SHA256` checks the installed source after local fixes, with
checkout line endings and terminal blank lines normalized. Host-specific mailbox, persistence,
stop, traffic and post-registration behavior lives in the adjacent adapter and
must not be added to the vendored file.

## Local fixes

- `reset-auth-submission-state-after-route-retry`: after the existing bounded
  `Try again` path succeeds, clear the password and OTP submission flags from
  the previous document. A recovered empty form can then be completed normally.
  Retry limits, selectors, timeouts, and browser transport are unchanged.

The production adapter deliberately disables the reference protocol-prefix,
protocol-tail and OpenBrowser branches.  Only the local headed Google Chrome
state machine represented by the captured successful run is supported.
