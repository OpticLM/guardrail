# @opticlm/guardrail

Native Node.js bindings for the `guardrail` cross-platform process sandbox.

```js
const { Sandbox } = require('@opticlm/guardrail')

const sandbox = await Sandbox.build({
  fs: [
    { kind: 'read-allow', path: '/usr' },
    { kind: 'read-allow', path: '/lib' },
    { kind: 'read-allow', path: '/etc/ssl' },
    { kind: 'execute-allow', path: '/usr/bin' },
    { kind: 'write-allow', path: '/tmp/work' },
  ],
  network: 'outbound-only',   // 'deny' | 'outbound-only' | 'full'
  ipc: 'strict',              // 'strict' | 'relaxed'
  memoryLimitMb: 256,
  env: { PATH: '/usr/bin:/bin' },
  windowsCacheNamespace: 'tools',
})

const child = sandbox.spawn('/usr/bin/mytool', ['--flag'])
const result = await child.wait()
// result: { code, signal, success, violation? }
if (!result.success && result.violation) {
  console.error(result.violation.summary)
  for (const s of result.violation.suggestions) console.error('  - ' + s)
}
```

## Notes
- The sandbox denies everything by default; grant exactly the access the child
  needs. `fs` rules are applied in array order, and later matching rules
  override earlier matching rules for the same right. An `"execute-allow"` rule
  does not imply read — add a `"read-allow"` rule for the binary and its shared
  libraries too. A `"write-allow"` rule does not imply read.
- stdio is inherited from the parent process. Output capture (piping) is not yet
  supported.
- `spawn(command, args, options)` remains available as a one-shot wrapper, but a
  reusable `Sandbox` avoids rebuilding platform policy state for repeated runs.
  Use `await Sandbox.build(options)` so expensive setup runs off the event loop.
- On Windows, `windowsCacheNamespace` separates cached AppContainer filesystem
  state. Use different namespaces for policies that may be active at the same
  time.
- `child.kill()` is best-effort once `wait()` is in flight: it sends SIGKILL on
  Unix and is unsupported on Windows in that state.

```js
const sandbox = await Sandbox.build({
  fs: [
    { kind: 'read-allow', path: '/workspace' },
    { kind: 'read-deny', path: '/workspace/secrets' },
    { kind: 'read-allow', path: '/workspace/secrets/public-schema.json' },
  ],
})
const child = sandbox.spawn('/usr/bin/mytool')
```
