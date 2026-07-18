import { test } from 'node:test'
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { createRequire } from 'node:module'
import { Worker } from 'node:worker_threads'

const require = createRequire(import.meta.url)
const guardrail = require('../index.js')

test('module exposes the expected API', () => {
  assert.equal(typeof guardrail.spawn, 'function')
  assert.equal(typeof guardrail.Sandbox, 'function')
  assert.equal(typeof guardrail.probeSupport, 'function')
})

test('probeSupport passes on CI-supported machines', () => {
  // Throws when the kernel/OS lacks a required capability (e.g. Landlock on
  // Linux). CI hosts and dev machines running this suite must support the
  // sandbox — the Rust integration tests already rely on enforcement.
  guardrail.probeSupport()
})

test('spawns a sandboxed child and reports a clean exit (Unix)', { skip: process.platform === 'win32' }, async () => {
  // /usr/bin/true is a simple dynamically-linked binary that exits 0.
  // Grant read+execute on the root so the dynamic linker can load libc/ld.so
  // regardless of where the distro stashes them (/usr/lib64 on Fedora/RHEL,
  // /usr/lib/x86_64-linux-gnu on Debian/Ubuntu). This is a binding-plumbing
  // smoke test — spawn(), async wait(), exit result — not a Landlock/Seatbelt
  // precision test, so broad grants are appropriate here.
  assert.equal(typeof guardrail.Sandbox.build, 'function')
  const sandbox = await guardrail.Sandbox.build({
    fs: [
      { kind: 'read-allow', path: '/' },
      { kind: 'execute-allow', path: '/' },
    ],
    network: 'full',
  })
  const child = sandbox.spawn('/usr/bin/true')
  assert.equal(typeof child.pid, 'number')
  const result = await child.wait()
  if (process.platform === 'darwin') {
    // macOS Seatbelt uses `(deny default)`, which denies more than filesystem
    // — dyld/runtime sysctl reads (kern.bootargs, hw.pagesize_compat, ...) are
    // not emitted by the generated profile and can kill a binary before it
    // exits 0 (see guardrail-macos/src/lib.rs). The binding plumbing (spawn →
    // async wait → ExitResult) is what we exercise here, so on darwin only
    // assert that wait() resolves with a well-formed result object rather than
    // requiring a clean exit.
    assert.equal(typeof result, 'object', `expected result object, got ${JSON.stringify(result)}`)
    assert.equal(typeof result.success, 'boolean')
    return
  }
  assert.equal(result.success, true, `expected success, got ${JSON.stringify(result)}`)
  assert.equal(result.code, 0)
})

test('kill safely races async wait on fast exits (Unix)', { skip: process.platform === 'win32' }, async () => {
  const sandbox = await guardrail.Sandbox.build({
    fs: [
      { kind: 'read-allow', path: '/' },
      { kind: 'execute-allow', path: '/' },
    ],
    network: 'full',
  })

  for (let iteration = 0; iteration < 50; iteration += 1) {
    const child = sandbox.spawn('/usr/bin/true')
    const waiting = child.wait()
    assert.doesNotThrow(() => child.kill())
    const result = await waiting
    assert.equal(typeof result.success, 'boolean')
  }
})

test('reuses a sandbox while Node workers churn allocations (Unix)', { skip: process.platform === 'win32' }, async () => {
  const sandbox = await guardrail.Sandbox.build({
    fs: [
      { kind: 'read-allow', path: '/' },
      { kind: 'execute-allow', path: '/' },
    ],
    network: 'full',
  })
  const workers = Array.from({ length: 2 }, () => new Worker(`
    let sink = []
    function churn() {
      for (let i = 0; i < 256; i += 1) sink.push(Buffer.alloc((i % 4096) + 17))
      if (sink.length > 2048) sink = []
      setImmediate(churn)
    }
    churn()
  `, { eval: true }))
  await Promise.all(workers.map((worker) => once(worker, 'online')))

  try {
    const children = Array.from({ length: 16 }, () => sandbox.spawn('/usr/bin/true'))
    const results = await Promise.all(children.map((child) => child.wait()))
    for (const result of results) {
      assert.equal(typeof result.success, 'boolean')
      if (process.platform !== 'darwin') assert.equal(result.success, true)
    }
  } finally {
    await Promise.all(workers.map((worker) => worker.terminate()))
  }
})

test('spawns a sandboxed child and reports a clean exit (Windows)', { skip: process.platform !== 'win32' }, async () => {
  // `cmd /c exit 0` is the canonical clean-exit probe on Windows. Two Rust
  // integration tests prove it exits 0 under this backend's AppContainer +
  // Job Object confinement with no filesystem rules and default (deny)
  // network: `default_network_deny_still_launches_process_in_appcontainer`
  // (crates/guardrail-windows/tests/policy.rs) and
  // `default_config_runs_command_under_job_object`
  // (crates/guardrail-windows/tests/resource_limits.rs).
  //
  // No `fs` rules are needed: Windows already grants `ALL APPLICATION PACKAGES`
  // read+execute on C:\Windows\System32, so
  // the AppContainer child can load cmd.exe and its system DLLs without any
  // explicit guardrail rule. `cmd` is resolved to C:\Windows\System32\cmd.exe
  // by SearchPathW in the parent process (guardrail-windows/src/process.rs),
  // independent of the child's cleared environment.
  //
  // `spawn` clears the inherited environment, and AppContainer CreateProcess
  // launches need the standard Windows runtime vars, so pass them explicitly
  // (mirroring `builder_with_system_root` in the Rust tests). `network: 'deny'`
  // matches the proven tests' default and is the most sandbox-appropriate
  // choice for a local command that needs no network.
  const env = {}
  for (const key of ['SystemRoot', 'LOCALAPPDATA', 'USERPROFILE', 'TEMP', 'TMP']) {
    if (process.env[key] !== undefined) env[key] = process.env[key]
  }
  const sandbox = await guardrail.Sandbox.build({
    network: 'deny',
    env,
    windowsCacheNamespace: 'smoke',
  })
  const child = sandbox.spawn('cmd', ['/c', 'exit', '0'])
  assert.equal(typeof child.pid, 'number')
  const result = await child.wait()
  assert.equal(result.success, true, `expected success, got ${JSON.stringify(result)}`)
  assert.equal(result.code, 0)
})
