import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { createRequire } from 'node:module'
import { once } from 'node:events'
import { text } from 'node:stream/consumers'
import { Worker } from 'node:worker_threads'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import * as guardrail from '../index.mjs'

const execFileAsync = promisify(execFile)
const require = createRequire(import.meta.url)
const guardrailCjs = require('../index.cjs')

test('module exposes the expected API', () => {
  for (const module of [guardrail, guardrailCjs]) {
    assert.equal(typeof module.spawn, 'function')
    assert.equal(typeof module.Sandbox, 'function')
    assert.equal(typeof module.probeSupport, 'function')
  }
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

test('inherits Node standard streams on Unix', { skip: process.platform === 'win32' }, async () => {
  // libuv marks Node's own descriptors close-on-exec. Run the binding in a
  // nested Node process whose three standard streams are pipes, then require
  // the sandboxed shell to read and write through those exact streams.
  const bindingUrl = new URL('../index.mjs', import.meta.url).href
  const darwinRuntimeProfile = fileURLToPath(
    new URL('../../guardrail-macos/tests/fixtures/runtime.sb', import.meta.url),
  )
  const script = `
    const guardrail = await import(${JSON.stringify(bindingUrl)})
    const sandbox = await guardrail.Sandbox.build({
      fs: [
        { kind: 'read-allow', path: '/' },
        { kind: 'execute-allow', path: '/' },
      ],
      network: 'full',
      darwinSandboxProfiles: process.platform === 'darwin'
        ? [${JSON.stringify(darwinRuntimeProfile)}]
        : undefined,
    })
    const child = sandbox.spawn('/bin/sh', [
      '-c',
      'IFS= read -r line; printf "stdout:%s\\n" "$line"; printf "stderr:%s\\n" "$line" >&2',
    ])
    const result = await child.wait()
    if (!result.success) throw new Error('sandboxed stdio probe failed: ' + JSON.stringify(result))
  `

  const { stdout, stderr } = await new Promise((resolve, reject) => {
    const nested = execFile(
      process.execPath,
      ['--input-type=module', '--eval', script],
      { encoding: 'utf8' },
      (error, childStdout, childStderr) => {
        if (error) {
          reject(error)
          return
        }
        resolve({ stdout: childStdout, stderr: childStderr })
      },
    )
    nested.stdin.end('guardrail-stdin-marker\n')
  })

  assert.match(stdout, /^stdout:guardrail-stdin-marker$/m)
  assert.match(stderr, /^stderr:guardrail-stdin-marker$/m)
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
  // explicit guardrail rule. Bare names like `cmd` are resolved against the
  // configured env's PATH (guardrail-windows/src/process.rs) — never the
  // parent's own lookup context — so System32 must be listed explicitly.
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
  if (process.env.SystemRoot !== undefined) {
    env.PATH = process.env.SystemRoot + '\\System32'
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

test('inherits Node standard output and error on Windows', { skip: process.platform !== 'win32' }, async () => {
  // Run the binding in a nested Node process whose stdout/stderr are pipes
  // owned by this test. The sandboxed cmd process must inherit those exact
  // handles for its markers to reach execFile's captured output.
  const bindingUrl = new URL('../index.mjs', import.meta.url).href
  const script = `
    const guardrail = await import(${JSON.stringify(bindingUrl)})
    const env = {}
    for (const key of ['SystemRoot', 'LOCALAPPDATA', 'USERPROFILE', 'TEMP', 'TMP']) {
      if (process.env[key] !== undefined) env[key] = process.env[key]
    }
    if (process.env.SystemRoot !== undefined) {
      env.PATH = process.env.SystemRoot + '\\\\System32'
    }
    const sandbox = await guardrail.Sandbox.build({
      network: 'deny',
      env,
      windowsCacheNamespace: 'smoke-stdio-' + process.pid,
    })
    const child = sandbox.spawn('cmd', [
      '/D',
      '/C',
      'echo guardrail-stdout-marker&echo guardrail-stderr-marker>&2',
    ])
    const result = await child.wait()
    if (!result.success) throw new Error('sandboxed stdio probe failed: ' + JSON.stringify(result))
  `

  const { stdout, stderr } = await execFileAsync(
    process.execPath,
    ['--input-type=module', '--eval', script],
    { encoding: 'utf8' },
  )

  assert.match(stdout, /^guardrail-stdout-marker\r?$/m)
  assert.match(stderr, /^guardrail-stderr-marker\r?$/m)
})

// ---- streamed stdio (stdin/stdout/stderr: 'pipe' | 'ignore') ----

const isWindows = process.platform === 'win32'
const darwinRuntimeProfile = fileURLToPath(
  new URL('../../guardrail-macos/tests/fixtures/runtime.sb', import.meta.url),
)

// Sandbox options able to run the platform shell: cmd on Windows (System32 is
// reachable through the built-in ALL APPLICATION PACKAGES grants), /bin/sh
// with broad read/execute grants elsewhere. The darwin runtime profile
// supplies the dyld/sysctl grants Seatbelt's (deny default) otherwise blocks.
function shellSandboxOptions(namespace) {
  if (isWindows) {
    const env = {}
    for (const key of ['SystemRoot', 'LOCALAPPDATA', 'USERPROFILE', 'TEMP', 'TMP']) {
      if (process.env[key] !== undefined) env[key] = process.env[key]
    }
    if (process.env.SystemRoot !== undefined) {
      env.PATH = process.env.SystemRoot + '\\System32'
    }
    return { network: 'deny', env, windowsCacheNamespace: namespace }
  }
  return {
    fs: [
      { kind: 'read-allow', path: '/' },
      { kind: 'execute-allow', path: '/' },
    ],
    network: 'full',
    darwinSandboxProfiles: process.platform === 'darwin' ? [darwinRuntimeProfile] : undefined,
  }
}

function spawnShell(sandbox, script, options) {
  if (isWindows) return sandbox.spawn('cmd', ['/D', '/C', script.windows], options)
  return sandbox.spawn('/bin/sh', ['-c', script.unix], options)
}

const echoMarkers = {
  windows: 'echo guardrail-out-marker&echo guardrail-err-marker>&2',
  unix: 'printf guardrail-out-marker; printf guardrail-err-marker >&2',
}

test("piped stdout and stderr are Readable streams; wait() is status-only", async () => {
  const sandbox = await guardrail.Sandbox.build(shellSandboxOptions('smoke-streams'))
  const child = spawnShell(sandbox, echoMarkers, { stdout: 'pipe', stderr: 'pipe' })
  assert.equal(child.stdin, null)
  const [out, err, result] = await Promise.all([
    text(child.stdout),
    text(child.stderr),
    child.wait(),
  ])
  assert.equal(result.success, true, `expected success, got ${JSON.stringify(result)}`)
  assert.equal(out.trim(), 'guardrail-out-marker')
  assert.equal(err.trim(), 'guardrail-err-marker')
  assert.equal(result.stdout, undefined, 'ExitResult no longer carries buffered output')
  assert.equal(result.stderr, undefined)
})

test("'ignore' output leaves no streams on the child", async () => {
  const sandbox = await guardrail.Sandbox.build(shellSandboxOptions('smoke-ignore'))
  const child = spawnShell(sandbox, echoMarkers, { stdout: 'ignore', stderr: 'ignore' })
  assert.equal(child.stdout, null)
  assert.equal(child.stderr, null)
  const result = await child.wait()
  assert.equal(result.success, true, `expected success, got ${JSON.stringify(result)}`)
})

test('streams only the piped stream', async () => {
  const sandbox = await guardrail.Sandbox.build(shellSandboxOptions('smoke-asym'))
  const child = spawnShell(
    sandbox,
    { windows: 'echo guardrail-out-marker', unix: 'printf guardrail-out-marker' },
    { stdout: 'pipe', stderr: 'ignore' },
  )
  assert.equal(child.stderr, null)
  const [out, result] = await Promise.all([text(child.stdout), child.wait()])
  assert.equal(result.success, true, `expected success, got ${JSON.stringify(result)}`)
  assert.equal(out.trim(), 'guardrail-out-marker')
})

test('one-shot spawn() attaches streams too', async () => {
  const options = { ...shellSandboxOptions('smoke-oneshot'), stdout: 'pipe' }
  const child = isWindows
    ? guardrail.spawn('cmd', ['/D', '/C', 'echo guardrail-out-marker'], options)
    : guardrail.spawn('/bin/sh', ['-c', 'printf guardrail-out-marker'], options)
  const [out, result] = await Promise.all([text(child.stdout), child.wait()])
  assert.equal(result.success, true, `expected success, got ${JSON.stringify(result)}`)
  assert.equal(out.trim(), 'guardrail-out-marker')
})

test('wait() is memoized and multi-awaitable', async () => {
  const sandbox = await guardrail.Sandbox.build(shellSandboxOptions('smoke-memo'))
  const child = spawnShell(
    sandbox,
    { windows: 'exit 0', unix: 'exit 0' },
    { stdout: 'ignore', stderr: 'ignore' },
  )
  const first = child.wait()
  const second = child.wait()
  assert.equal(first, second, 'wait() must return the same promise')
  const result = await first
  assert.equal(result.success, true, `expected success, got ${JSON.stringify(result)}`)
  assert.equal((await child.wait()).success, true, 'a later wait() resolves too')
})

test('drives a persistent shell interactively (state persists across turns)', async () => {
  const sandbox = await guardrail.Sandbox.build(shellSandboxOptions('smoke-shell'))
  const shell = isWindows
    ? sandbox.spawn('cmd', ['/D', '/Q'], { stdin: 'pipe', stdout: 'pipe', stderr: 'pipe' })
    : sandbox.spawn('/bin/sh', [], { stdin: 'pipe', stdout: 'pipe', stderr: 'pipe' })
  const exited = shell.wait()

  // Keep one manual iterator across turns; its return() is never called, so
  // the stream survives between reads — the point of a persistent shell.
  shell.stdout.setEncoding('utf8')
  const output = shell.stdout.iterator({ destroyOnReturn: false })
  async function readUntil(marker) {
    let seen = ''
    while (!seen.includes(marker)) {
      const { value, done } = await output.next()
      assert.ok(!done, `stdout ended before ${JSON.stringify(marker)}; saw: ${seen}`)
      seen += value
    }
    return seen
  }

  if (isWindows) {
    shell.stdin.write('set GUARDRAIL_MARK=guardrail-persists\r\n')
    shell.stdin.write('echo turn-one-%GUARDRAIL_MARK%\r\n')
    await readUntil('turn-one-guardrail-persists')
    shell.stdin.write('echo turn-two-%GUARDRAIL_MARK%\r\n')
    await readUntil('turn-two-guardrail-persists')
  } else {
    shell.stdin.write('GUARDRAIL_MARK=guardrail-persists\n')
    shell.stdin.write('echo "turn-one-$GUARDRAIL_MARK"\n')
    await readUntil('turn-one-guardrail-persists')
    shell.stdin.write('echo "turn-two-$GUARDRAIL_MARK"\n')
    await readUntil('turn-two-guardrail-persists')
  }

  // EOF on stdin ends the shell session.
  shell.stdin.end()
  const result = await exited
  assert.equal(result.success, true, `shell exit: ${JSON.stringify(result)}`)
})

test('kill() unblocks a persistent child and ends its streams', async () => {
  const sandbox = await guardrail.Sandbox.build(shellSandboxOptions('smoke-kill'))
  const child = isWindows
    ? sandbox.spawn('cmd', ['/D', '/Q'], { stdin: 'pipe', stdout: 'pipe' })
    : sandbox.spawn('/bin/sh', [], { stdin: 'pipe', stdout: 'pipe' })
  const exited = child.wait()

  child.kill()
  const [out, result] = await Promise.all([text(child.stdout), exited])
  assert.equal(result.success, false, 'a killed child must not exit cleanly')
  assert.equal(typeof out, 'string', 'stdout reaches EOF after the kill')
})
