# @opticlm/guardrail

Native Node.js bindings for the `guardrail` cross-platform process sandbox.

```js
const { spawn } = require('@opticlm/guardrail')

const child = spawn('/usr/bin/mytool', ['--flag'], {
  fs: [
    { kind: 'read', path: '/usr' },
    { kind: 'read', path: '/lib' },
    { kind: 'read', path: '/etc/ssl' },
    { kind: 'execute', path: '/usr/bin' },
    { kind: 'write', path: '/tmp/work' },
  ],
  network: 'outbound-only',   // 'deny' | 'outbound-only' | 'full'
  ipc: 'strict',              // 'strict' | 'relaxed'
  memoryLimitMb: 256,
  env: { PATH: '/usr/bin:/bin' },
})

const result = await child.wait()
// result: { code, signal, success, violation? }
if (!result.success && result.violation) {
  console.error(result.violation.summary)
  for (const s of result.violation.suggestions) console.error('  - ' + s)
}
```

## Notes
- The sandbox denies everything by default; grant exactly the access the child
  needs. `fs` grants are applied in array order. An `"execute"` grant does not
  imply read — add a `"read"` grant for the binary and its shared libraries too.
- stdio is inherited from the parent process. Output capture (piping) is not yet
  supported.
- `child.kill()` is best-effort once `wait()` is in flight: it sends SIGKILL on
  Unix and is unsupported on Windows in that state.
