# coolify2shell
Authenticated RCE in Coolify's terminal websocket — arbitrary code execution on Coolify's own control-plane container


# Full Disclosure: Authenticated RCE in Coolify's terminal websocket — arbitrary code execution on Coolify's own control-plane container, silently patched as "harden terminal command handling"

> **tl;dr** On Aug 7, 2026 I reported to Coolify a vulnerability that let any team admin with terminal access execute arbitrary code on the `coolify-realtime` container — a component of the Coolify control plane itself — by injecting an SSH `ProxyCommand` through the terminal websocket. That container has every team's private SSH keys bind-mounted, so the bug also enabled stealing all keys and pivoting via SSH to any server managed by the instance, including servers of teams the attacker doesn't belong to. The fix landed on Aug 28, 2026 ([commit `aff581043`](https://github.com/coollabsio/coolify/commit/aff581043f095c7adbbfb1adfbd3aa94023da792)) and shipped in **v4.3.15 (Sep 2, 2026)** as a commit titled *"fix(realtime): harden terminal command handling"* — no security advisory, no CVE, no mention anywhere that this was a code-execution issue, and no recommendation for users of affected versions to rotate their keys. In total, over the entire lifecycle of this report — before, during, and after the fix — the **only** communication I ever received from Coolify was a Discord message telling me they'd get to my email "eventually". Nobody ever followed up. Not to confirm receipt, not to say it was fixed, not ever.

---

## Unofficial advisory

| | |
|---|---|
| **Product** | Coolify (self-hosted) — terminal websocket server |
| **Vulnerable component** | `coolify-realtime` container (terminal websocket server), `handleCommand()` / `extractSshArgs()` in `terminal-utils.js` |
| **Affected versions** | Coolify **≤ v4.3.14** (last vulnerable release: Aug 18, 2026), when at least one server has the terminal enabled |
| **Fixed in** | Commit [`aff581043`](https://github.com/coollabsio/coolify/commit/aff581043f095c7adbbfb1adfbd3aa94023da792) ("fix(realtime): harden terminal command handling"), merged **Aug 28, 2026**; first fixed release: **v4.3.15, Sep 2, 2026** |
| **Later hardening** | From v4.4.0 (Oct 6, 2026) the terminal server runs inside the main Coolify container; the sidecar with the SSH key mount no longer exists |
| **Prerequisites** | Authenticated team admin/owner passing the `canAccessTerminal` gate; ≥ 1 server with terminal enabled |
| **Impact** | Arbitrary command execution on the `coolify-realtime` control-plane container; theft of **all teams'** private SSH keys mounted in it; cross-tenant SSH pivot to any managed server |
| **Not possible** | Direct code execution on the Docker host (no docker socket mounted in the container) — but stolen keys yield root access to every managed server anyway |
| **Vendor advisory / CVE** | **None exists as of publication** |

If you are on ≤ v4.3.14: update and **rotate every SSH key managed by Coolify** — see Recommendations at the bottom.

---

## Contact timeline — the only responses I ever got

- **Aug 7, 2026** — Emailed the Coolify security contact: full report with root cause, live-confirmed PoC, impact analysis, and three concrete remediation options. No reply.
- **Aug 14, 2026** — Follow-up email. No reply.
- **Aug 18, 2026** — Twitter/X DM. No reply.
- **Aug 24, 2026** — Pinged the official Discord. The reply, verbatim:
  > *"email is the way to go. Andras gets **a lot** of emails security related (often AI generated), so going through them takes time. so you won't always get a immediate response until he manages to take a look at your email specifically."*
- **Aug 28, 2026** — Fix commit lands in the public repo. **Nobody told me.** I found it by diffing the repository myself.
- **Sep 2, 2026** — v4.3.15 released with the fix. No advisory, no changelog entry about an RCE, no note to users, no reply to me.
- **To date** — I have never received any further communication from Coolify about this report. No acknowledgment, no "we've fixed it, thanks", no request to confirm details, nothing. Every fact in this post after Aug 24 comes from my own diffing and testing of the public repository.

I want to be fair on one point, because a credible disclosure should be: from my first email (Aug 7) to the fix commit (Aug 28) is **21 days** — an entirely reasonable turnaround. This post is not an accusation of negligence on the fix itself. The failure is everything around it: a reporter left with zero acknowledgment across three channels, a security-relevant patch disguised as generic "hardening", and thousands of self-hosted instances given no way to learn they should update and rotate keys.

## The vulnerability

### Affected versions
- Coolify **≤ v4.3.14** with the terminal feature enabled for at least one server.
- At the time, the terminal websocket server shipped inside the `coolify-realtime` container.

### Root cause

The terminal websocket server validated the SSH **target host** against the team's authorized IP list, but passed every SSH option to `pty.spawn()` **unfiltered**:

```js
const sshArgs = extractSshArgs(commandString);       // parses options — WITHOUT filtering
const targetHost = extractTargetHost(sshArgs);
if (!isAuthorizedTargetHost(targetHost, userSession.authorizedIPs)) { reject(); }
// ...
const ptyProcess = pty.spawn('ssh', sshArgs.concat([hereDocContent]), options);
```

`extractSshArgs()` (in `terminal-utils.js`) preserved every `-o` option verbatim, including `-o ProxyCommand='...'`. SSH runs `ProxyCommand` through the local shell **on the terminal container, before any SSH connection is attempted**. The host check verified *where* the connection goes; the attacker controlled *how* — and that "how" was arbitrary code on the container.

Explicit blast radius, because precision matters:

- ✅ Arbitrary command execution **inside the `coolify-realtime` container** — a Coolify control-plane component, not a customer-managed server.
- ✅ That container bind-mounts all private SSH keys:
  ```yaml
  volumes:
    - /data/coolify/ssh:/var/www/html/storage/app/ssh
  ```
  Keys of **every team on the instance** — tenants the attacker, as a mere team admin, normally cannot even see — plus known_hosts and multiplexing sockets.
- ❌ Not directly the Docker host: no docker socket was mounted. The host is not "pwned" by this bug per se. However, exfiltrating other teams' keys gives root SSH access to their servers, so the practical result is full cross-tenant compromise of every managed machine using stolen credentials rather than a container escape.

That consequence is not "hardenable edge case": in a multi-tenant product, letting one tenant's admin silently take every other tenant's keys and servers is a fundamental isolation failure.

### The PoC

From the browser console on the terminal page, against your own authorized server so the host check passes:

```js
// core message; full runnable PoC available on request
const sshCmd = [
  'timeout 30 ssh',
  "-o ProxyCommand='echo 1337 > /tmp/pocced.txt'",   // <-- injected; runs on coolify-realtime
  '-o StrictHostKeyChecking=no',
  '-o UserKnownHostsFile=/dev/null',
  '-o PasswordAuthentication=no',
  '-o ConnectTimeout=5',
  '-o LogLevel=ERROR',
  '-p 22',
  "'root'@'<YOUR-AUTHORIZED-SERVER-IP>' 'bash -se' << \\E1",
  'echo done',
  'E1',
].join(' ');

socket.send(JSON.stringify({ command: [sshCmd] }));
```

Live confirmation (Docker Desktop, `docker-compose.windows.yml`):

```
$ docker exec coolify-realtime cat /tmp/pocced.txt
1337
```

The PTY connects normally to my own server — the host check passes, the injection executes first, and nothing in the UI shows that anything happened.

Attack scenarios:

1. **SSH key exfiltration** — one `ProxyCommand` copies all keys out of `/var/www/html/storage/app/ssh/keys/` (out-of-band, or straight into the terminal output).
2. **Cross-tenant pivot** — SSH from the same websocket session to any other team's server using their stolen key.
3. **Arbitrary RCE on the control-plane container**, including a persistent foothold.

### Remediation options I proposed on Aug 7

- **A:** allowlist `ProxyCommand` values — only the Cloudflare tunnel pattern `cloudflared access ssh --hostname %h`.
- **B:** force a restricted SSH config (`-F /dev/null`).
- **C:** filter dangerous options in `extractSshArgs()` (`ProxyCommand`, `LocalCommand`, `RemoteCommand`, `PermitLocalCommand`, …).

## How the fix actually shipped

- **Aug 28, 2026** — commit [`aff581043`](https://github.com/coollabsio/coolify/commit/aff581043f095c7adbbfb1adfbd3aa94023da792) by the Coolify maintainer: *"fix(realtime): harden terminal command handling"*. It adds ~130 lines implementing exactly a stricter version of the options I had proposed: a full **allowlist** of every SSH argument — `ProxyCommand` pinned to the exact `cloudflared access ssh --hostname %h` value, `-F` accepted only as `/dev/null`, `-i` restricted to Coolify's key paths, duplicate options rejected, newline/NUL bytes rejected, and the PTY process environment reduced to `PATH` plus the two Cloudflare token variables — wired into `handleCommand()` before `pty.spawn()`, with tests covering the exact injected payload from my report.
- **Sep 2, 2026** — shipped in **v4.3.15**. The release notes say nothing about an RCE, nothing about the injection, and nothing that would tell an administrator of an affected instance why they should update urgently and whether they should rotate their keys.
- No security advisory. No CVE request. No response to the reporter — before, during, or after.

I verified the fix technically: I re-executed my original PoC flow against the patched code path and it is rejected (`Invalid SSH command: Unsupported SSH arguments`) before any process is spawned; every bypass variant I attempted is rejected; the upstream test suite passes and includes regression tests for this attack. Whoever picked up the report understood it and fixed it **well**. That makes the silence harder to explain, not easier: the engineering was done properly, while the reporter was never told and the users were never warned.

## Why this posting is warranted

- **21 days to a solid fix** — good. **Zero substantive communication in 3+ months**, ever — not acceptable. Disclosure norms are bilateral: reporters commit to quiet reporting and a disclosure window; vendors commit to acknowledging, crediting, and warning users. One side held the deal.
- A commit message like *"harden terminal command handling"* is indistinguishable from routine cleanup — it is precisely the kind of message you write when you **don't want** users to know what changed. If Coolify's policy is to avoid advisories, fine — but users of ≤ v4.3.14 running with terminal enabled had keys that any team admin could silently exfiltrate, and nobody was ever told to rotate them. They will learn about this here, or never.
- The Discord reply also revealed something worth naming: security emails get processed by one person, among "a lot of emails (often AI generated)", whenever he gets to them. That is a single point of failure with no triage, no tracking, and no obligation to ever respond — the exact conditions under which reports are lost.

## Recommendations

**If you run Coolify ≥ v4.3.15:** you are past the vulnerable code. Keep updating; in particular from v4.4.0 the terminal server no longer runs in a sidecar with the SSH keys mounted.

**If you are or were on ≤ v4.3.14 with the terminal enabled:**
1. Update immediately.
2. Treat the keys under `/data/coolify/ssh/keys/` as potentially compromised: **rotate every SSH key managed by Coolify**, on the Coolify side and in `authorized_keys` on every server they grant access to.
3. Audit managed servers for unknown `authorized_keys` entries, new cron jobs, and unexpected connections — especially if your instance had multiple teams or admins you don't fully trust.
4. If you're a Coolify team admin reading this and you never knew your instance's terminal container held **every** team's keys: that mount is gone in current versions, which is exactly the kind of thing an advisory exists to tell you.

**For the Coolify team:** Acknowledge reports, even with two sentences. Ship security fixes as security fixes — an advisory for v4.3.15 costs one paragraph and would have protected your users. And someone should still check that inbox. Do better.

## Timeline 

| Date | Event |
|---|---|
| 2026-03-10 | Vulnerable `extractSshArgs()` code appears in the repo (`coolify-realtime` image) |
| 2026-08-07 | Report sent by email (full report + PoC + remediation options). No reply |
| 2026-08-14 | Follow-up email. No reply |
| 2026-08-18 | Twitter/X DM. No reply |
| 2026-08-24 | Discord ping; only response ever received: *"email is the way to go. Andras gets a lot of emails security related…"* |
| 2026-08-28 | Fix commit [`aff581043`](https://github.com/coollabsio/coolify/commit/aff581043f095c7adbbfb1adfbd3aa94023da792) — *"fix(realtime): harden terminal command handling"*. No notification to the reporter |
| 2026-09-02 | **v4.3.15 released with the fix** — no advisory, no CVE, no note to users |
| 2026-10-06 | v4.4.0 moves the terminal server out of the key-mounting sidecar |
| 2026-11-19 | No further communication from Coolify. This disclosure |


