# sbx-policy

`sbx-policy` is a lightweight, project-level network allowlist manager for [Docker Sandbox](https://www.docker.com/products/docker-sandboxes/) (`sbx`).

## What it does

Docker Sandbox exposes network policies through `sbx policy allow network`, but those policies are not naturally project-scoped or declaratively versioned with your code. `sbx-policy` bridges that gap by:

1. Keeping a declarative `.sbx/policy.yaml` file in your project.
2. Warning you when the allowlist changes since you last approved it.
3. Synchronizing the desired allowlist to a **specific sandbox** (never globally).

After syncing, you use `sbx` normally — `sbx-policy` does not wrap or replace `sbx run`.

## Installation

```bash
go install github.com/daliendev/sbx-policy@latest
```

Or clone and build:

```bash
git clone https://github.com/daliendev/sbx-policy.git
cd sbx-policy
go build -o sbx-policy .
```

### Add to your PATH

If you are running from the cloned repository, add it to your `PATH` so you can invoke `sbx-policy` from any project:

```bash
# In ~/.bashrc, ~/.zshrc, or ~/.bash_profile
export PATH="/path/to/sbx-policy:$PATH"
```

Then reload your shell:

```bash
source ~/.bashrc  # or ~/.zshrc
```

## Quick start

```bash
# Create a new policy file in your project
sbx-policy init

# Fill in the policy file (or edit it by hand)
sbx-policy allow github.com registry.npmjs.org
sbx-policy ports add 8080:3000
sbx-policy sandbox set my-project-sandbox

# Validate the policy file
sbx-policy check

# Sync the allowlist to your sandbox (warns if it changed)
sbx-policy sync --sandbox my-project-sandbox

# Now use sbx as usual
sbx run opencode .
```

## `.sbx/policy.yaml`

This is the project policy file. It lives in your repository so it can be versioned and reviewed.

```yaml
version: 1
sandbox: my-project-sandbox

network_allowlist:
  - api.opencode.ai
  - registry.npmjs.org
  - github.com

ports:
  - "8080:3000"
  - "3000"
```

Rules:

- `version` must be `1`.
- `sandbox` is optional. When set, `sbx-policy sync` targets this sandbox automatically. You can override it with the `--sandbox` CLI flag.
- `network_allowlist` must be a list of non-empty strings.
- Entries may not contain commas or whitespace (matching Docker Sandbox requirements).
- Optional `:port` suffixes are allowed.
- Wildcard hostnames such as `*.githubusercontent.com` are preserved.
- `ports` is optional. Each entry is either `host:sandbox` (e.g. `8080:3000`) or just `sandbox` (lets the OS pick a free host port).

## Commands

| Command | Description |
|---------|-------------|
| `sbx-policy init` | Create `.sbx/policy.yaml` if it does not exist. |
| `sbx-policy check` | Validate YAML syntax and schema. |
| `sbx-policy allow <host>...` | Add hosts to the network allowlist. Hosts may be space-separated, comma-separated within one argument, or both. |
| `sbx-policy ports add <mapping>...` | Add port mappings to the policy. |
| `sbx-policy sandbox set <name>` | Set the target sandbox name in the policy. |
| `sbx-policy sync` / `sync up` | Compare allowlist against remembered state, prompt if changed, then push `.sbx/policy.yaml` to `sbx` for a specific sandbox. |
| `sbx-policy sync down` | Pull the network allowlist and ports already configured in `sbx` for a sandbox into `.sbx/policy.yaml`, prompting if it would change the file. |

The `allow`, `ports add`, and `sandbox set` commands update `.sbx/policy.yaml`
and, in an interactive terminal, offer to run `sbx-policy sync` right away (in
non-interactive environments they print a hint instead).

## Example workflow

```bash
$ sbx-policy init
✓ Created .sbx/policy.yaml

$ cat .sbx/policy.yaml
version: 1
sandbox: my-project-sandbox
network_allowlist:
  - github.com
  - registry.npmjs.org

# First sync without a sandbox known
$ sbx-policy sync
Error: No sandbox specified for this project.

sbx-policy sync scopes network rules to individual sandboxes
instead of applying them globally.

To specify a sandbox, use one of:
  1. Pass --sandbox <name> to sbx-policy sync
  2. Add 'sandbox: <name>' to .sbx/policy.yaml

# After creating a sandbox (or specifying it explicitly)
$ sbx-policy sync --sandbox my-project-sandbox
No previous network policy found for this project.

Sandbox: my-project-sandbox
Network allowlist:
  • github.com
  • registry.npmjs.org

Initialize and continue? [Y/n] y
✓ Network allowlist synchronized to sandbox my-project-sandbox

# Now run your sandboxed tool as usual
$ sbx run opencode .

# Later, the policy file changes
$ sbx-policy sync
⚠ Network allowlist changed since last approval

Sandbox: my-project-sandbox

  + evil.com

Continue with the updated policy? [y/N] n
Aborted.
```

If you want a single command for daily use, create a shell alias or function. Make sure your policy file declares the sandbox so you do not have to pass `--sandbox` every time:

```bash
sbx-run() {
  sbx-policy sync && sbx run "$@"
}
```

Then:

```bash
sbx-run opencode .
```

## Pulling in the other direction

`sbx-policy sync` (== `sync up`) is a one-way push: it makes `sbx` match `.sbx/policy.yaml`.
If a sandbox's network policy was changed directly through `sbx` (or you're adopting
`sbx-policy` for a sandbox that already has rules), use `sync down` to go the other way —
it makes `.sbx/policy.yaml` match what `sbx` currently has for that sandbox:

```bash
$ sbx-policy sync down --sandbox my-project-sandbox
⚠ Sandbox my-project-sandbox differs from .sbx/policy.yaml

Network allowlist:
  + registry.npmjs.org
  + deb.debian.org

Overwrite .sbx/policy.yaml with the sandbox's current state? [y/N] y
✓ .sbx/policy.yaml updated from sandbox my-project-sandbox
```

Only rules scoped specifically to that sandbox are pulled in — the host-wide defaults every
sandbox gets (npm/PyPI/GitHub/etc.) are never written into a project's `.sbx/policy.yaml`.

## How remembered state works

`sbx-policy` stores the last known/approved allowlist (and the associated sandbox name) in a local user-level directory (e.g. `~/.config/sbx-policy/`). This state is **not** committed to Git.

When you run `sbx-policy sync`, the tool compares the current `.sbx/policy.yaml` against the remembered state. If the allowlist changed, it shows a diff and asks for confirmation before touching `sbx`.

The remembered sandbox name is used as a fallback when neither the `--sandbox` flag nor the `sandbox` field in `policy.yaml` is set.

**Important:** This is a change-detection convenience, not a security boundary. An agent that can modify `.sbx/policy.yaml` can also modify your source code. The actual sandbox enforcement remains Docker Sandbox's responsibility.

## Security model

- The project policy file is **declarative configuration**, not a security boundary.
- The remembered local state is only a **user warning mechanism**.
- `sbx-policy` does not implement cryptographic signatures, Git commit verification, or policy signing.
- Docker Sandbox (`sbx`) is responsible for the actual network enforcement.

## Development

```bash
go test ./...
go build .
```

## License

MIT
