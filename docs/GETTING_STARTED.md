# Getting started with jig

For gigue teammates who just want to talk to the team. You do not need to know Rust.
Written for macOS.

## What jig is

jig is a chat tool we built ourselves. You type in a terminal window, your teammates see
it, they type back.

There is no account and no password. The first time you run it, jig makes a key for you
on your own laptop, and every message you send is signed with that key — so people can
tell a message really came from you.

It only works inside the company tailnet. A tailnet is our private network: your laptop
and the jig server can see each other, and nothing on the public internet can. If you
are not on the tailnet, jig cannot reach anything.

## Before you start

**1. Tailscale, installed and approved.**

This is the first thing that will stop you, and you cannot fix it yourself. Install
Tailscale and sign in, then **ask DJ to approve your device** on the tailnet. Until he
does, every jig command will fail to connect.

Check it:

```bash
tailscale status
```

You should see a line containing `jig-vps`. If you do not, you are not approved yet.

**2. The `jig` binary.**

There is no download today. `releases.jig.onl` is not serving anything yet and there are
no GitHub releases, so ignore anything you read about `curl | sh`. Two real options:

**Option A — ask DJ for a binary.** Fastest. When you get it, macOS will refuse to run it
because it came from another machine and is not signed by a registered Apple developer.
Clear that flag once:

```bash
xattr -d com.apple.quarantine ./jig
```

Skipping this does not give you a nice error — the process is killed on the spot. You get
`zsh: killed: ./jig` or just silence.

**Option B — build it yourself.** About 15 minutes the first time, then seconds. You need
the repo (ask DJ for access; it is private) and Rust.

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

```bash
git clone git@github.com:jig-protocol/jig.git && cd jig/repos
```

```bash
cargo +stable build -p jig-cli
```

The binary lands at `repos/target/debug/jig`. Copy it somewhere on your `PATH` (e.g.
`~/bin/jig`) so you can type `jig` instead of the full path. jig needs Rust 1.94 or newer;
`+stable` makes sure you get a new enough one.

## First run

Three commands, once, in order.

```bash
jig init yourname
```

```
generated DID: did:jig:zaqqbbbhlq5caly6am4luxoqfamvn7hdqtr7o6u655kz22fhfjqpa
keyfile: ~/.jig/keys/did:jig:zaqqbbbhlq5caly6am4luxoqfamvn7hdqtr7o6u655kz22fhfjqpa.key
wrote ~/.jig/cli.toml (nickname: yourname)
```

That made you an identity. Two things worth understanding:

- A **DID** is your name in jig's eyes. It is your public key written out as text — a
  61-character string starting `did:jig:z`. It is not secret; it is how other people
  verify your messages.
- `~/.jig/keys/<did>.key` is the matching **private** key. It is the only copy. There is
  no password reset and no recovery. If you lose that file you lose that identity and
  have to start again as a new person.

So back it up now — into 1Password, or anywhere you keep secrets:

```bash
cp -R ~/.jig ~/Desktop/jig-backup
```

Next, point jig at our server. **It must be `https://`.** Plain `http://` fails with a
confusing parser error, not "wrong protocol".

```bash
jig server set https://jig-vps.tail323521.ts.net:7117
```

```
server set: https://jig-vps.tail323521.ts.net:7117
```

Now join the room:

```bash
jig chat '#gigue'
```

Keep the quotes around `'#gigue'`. Without them your shell throws away everything after
the `#`.

## Using the chat window

This is what you get:

```
┌#gigue──────────────────────────────────────────────────────────────────────┐
│14:22  did:jig:z4rhh3…: first real message on the VPS                       │
│14:22  dj: alice sees you, bob                                              │
│14:35  claudetest: hello from the onboarding-guide dry run                  │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
┌input — Enter to send, Ctrl+Q or Esc to quit────────────────────────────────┐
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

- **Type and press Enter** to send.
- **Ctrl+Q or Esc** quits. (Ctrl+C also works.)
- **Left / Right / Home / End** move the cursor in the input box.
- **You cannot scroll.** There is no scroll-back — the pane always shows the newest
  messages and older ones fall off the top. Make your terminal window taller to see more,
  or use `jig tail` (below), which prints into your terminal's own scrollback.
- **On opening** you get the last 100 messages in the channel, so you can catch up.

### Making names readable

Notice the difference above: `dj` and `claudetest` show as names, but the third person
shows as `did:jig:z4rhh3…`. jig does not have a directory of who is who. It only shows a
name if *you* have written that person's DID down in your own address book.

Your own name is filled in for you by `jig init`. Everyone else you add by hand. Open
`~/.jig/cli.toml` in any text editor and add lines under `[contacts]`:

```toml
[contacts]
"did:jig:zaqqbbbhlq5caly6am4luxoqfamvn7hdqtr7o6u655kz22fhfjqpa" = "yourname"
"did:jig:zbvz24e3dyq76m5pndn6o3y4uu4lbltfvmkbelegvnrrmn72ltkdq" = "dj"
```

The key must be the person's **full** DID, in quotes — the shortened `did:jig:z4rhh3…`
form in the chat pane will not match. So you have to ask them for it (they can read theirs
out of their own `~/.jig/cli.toml`). Restart `jig chat` to pick up the change.

Yes, this is annoying. It is a known rough edge, not something you are doing wrong.

## Other commands

Send one message and exit — handy in scripts:

```bash
jig send --channel '#gigue' "deploy finished"
```

It prints the message's ID and nothing else:

```
bafkr4ie4g5wia2dmkmwtinzclm37dt5ylkrkbiaoakmofbbrgl2buk7vku
```

Watch a channel as plain scrolling text, no window frame:

```bash
jig tail --channel '#gigue'
```

```
14:22  did:jig:z4rhh3…: first real message on the VPS
14:22  dj: alice sees you, bob
Tailing #gigue on https://jig-vps.tail323521.ts.net:7117... (Ctrl-C to exit)
```

See what channels exist:

```bash
jig channel list
```

```
#gigue    open        did:jig:zbvz24e3dyq76m5pndn6o3y4uu4lbltfvmkbelegvnrrmn72ltkdq
```

The third column is the DID of whoever created the channel — currently the easiest way to
get someone's full DID for your `[contacts]` list.

Make a new channel (this also makes it your default channel, so later commands without
`--channel` go there):

```bash
jig channel create '#my-project'
```

Add yourself to a channel's member list:

```bash
jig channel join '#gigue'
```

**`jig read` does not work.** It asks the server for a route that is switched off, and you
get `404 Not Found`. Use `jig chat` or `jig tail` instead. Do not go looking for a flag to
turn that route back on — it is off for a reason.

**`jig --version` does not work either.** It is not implemented yet.

## When it breaks

Errors I reproduced while writing this guide, unless marked otherwise.

| What you see | What it means | Fix |
|---|---|---|
| `failed to connect: IO error: failed to lookup address information: nodename nor servname provided, or not known` | Your Mac cannot even resolve the server's name. Tailscale is off, or your device is not approved. | Start Tailscale; run `tailscale status` and look for `jig-vps`. If it is missing, ask DJ to approve you. |
| `failed to connect: WebSocket protocol error: httparse error: invalid HTTP version` | You used `http://` instead of `https://`. | `jig server set https://jig-vps.tail323521.ts.net:7117` |
| `invalid HTTP version parsed` on `jig channel list` | Same cause: `http://` instead of `https://`. | As above. |
| `Error: connection lost while subscribed to #gigue — the server closed the stream` | The server restarted or the network blipped. **jig does not reconnect by itself** — it exits and you are out of the room. | Re-run `jig chat '#gigue'`. To have it come back automatically, run `scripts/jig-room.sh '#gigue'` from the repo instead; it just re-launches chat every time the connection drops. |
| `Connection refused (os error 61)` | Something is listening at that address but not jig, or nothing is. Usually a wrong URL or port. | Check `jig server set` used the exact URL above. |
| Any error mentioning `127.0.0.1:7117` | You never ran `jig server set`, so jig is still looking for a server on your own laptop. | Run the `jig server set` command. |
| `zsh: killed: ./jig`, or the command produces no output at all | macOS quarantine on a binary DJ sent you. | `xattr -d com.apple.quarantine ./jig` |
| `404 Not Found for url (.../blocks?limit=50)` | You ran `jig read`. It is broken. | Use `jig chat` or `jig tail`. |
| `cli config already exists at ~/.jig/cli.toml. Pass --force to overwrite.` | You ran `jig init` a second time. It is refusing to throw away your existing key. | Nothing — you are already set up. Only use `--force` if you genuinely want a brand-new identity. |
| Nothing happens. `jig send` prints an ID, nobody replies. | **Most likely a typo in the channel name.** jig does not check that a channel exists — it happily accepts messages into `#gigeu` and nobody is watching there. | `jig channel list` and copy the name exactly. |
| Tailscale is running and approved, but jig hangs then times out | Not reproduced — inferred. Probably the server itself is down. | Ask DJ; `curl https://jig-vps.tail323521.ts.net:7117/healthz` should print `ok`. |

## What jig is NOT, yet

Read this before you type anything sensitive into it.

- **Your messages are not encrypted.** They are *signed*, which proves who wrote them.
  That is a different thing. The server stores them in readable form and anyone who can
  read the server can read your messages.
- **There are no permissions.** Anyone on the tailnet can read and write every channel.
  That includes channels marked "restricted", which look membership-gated but are not
  actually enforced yet. Assume everything you write is visible to everyone on the
  tailnet.
- **No mobile app and no web page.** Terminal only, on a machine that is on the tailnet.
- **No notifications.** If `jig chat` is not open, you will not know a message arrived.
  You will see it in the last-100 backlog next time you open the channel.
- **No auto-reconnect.** A dropped connection puts you back at your shell prompt.
- **No message history beyond the last 100** in the chat window, and no search.

Treat it as an internal toy that works: fine for coordinating, wrong for anything you
would not want the whole company to read.

## Getting help

Ask DJ. If something looks broken, include the exact error text — every failure above is
distinguishable by its wording.
