// Public API of @opticlm/guardrail.
//
// Wraps the generated Node-API loader (binding.js) so piped standard streams
// surface as real Node streams: the native layer exposes per-stream promise
// primitives (readStdout/readStderr/writeStdin/endStdin), and this wrapper
// composes them into Readable/Writable objects with ordinary backpressure.

import { Readable, Writable } from 'node:stream'

import {
  Sandbox as NativeSandbox,
  spawn as nativeSpawn,
  cleanupWindowsNamespace,
  probeSupport,
  windowsHostSetupConfigured,
} from './binding.js'

export { cleanupWindowsNamespace, probeSupport, windowsHostSetupConfigured }

/**
 * Handle to a spawned, sandboxed child process.
 *
 * `stdin`, `stdout`, and `stderr` are Node streams for the standard streams
 * spawned with `'pipe'`, and `null` otherwise.
 */
export class SandboxChild {
  #native
  #exit
  /** Writable connected to the child's piped stdin, or null. */
  stdin
  /** Readable connected to the child's piped stdout, or null. */
  stdout
  /** Readable connected to the child's piped stderr, or null. */
  stderr

  constructor(native, launch) {
    this.#native = native
    this.stdin = launch?.stdin === 'pipe' ? makeStdinWritable(native) : null
    this.stdout = launch?.stdout === 'pipe' ? makeReadable(() => native.readStdout()) : null
    this.stderr = launch?.stderr === 'pipe' ? makeReadable(() => native.readStderr()) : null
  }

  /** OS process id of the child. */
  get pid() {
    return this.#native.pid
  }

  /**
   * Resolve with the child's `ExitResult` once it exits. Memoized: every call
   * returns the same promise, so it can be awaited any number of times (e.g.
   * once at spawn to monitor a persistent child, again at shutdown). Exit
   * status only — piped output is read from the streams.
   */
  wait() {
    this.#exit ??= this.#native.wait()
    return this.#exit
  }

  /**
   * Kill the child immediately: SIGKILL on Unix, Job Object termination (the
   * whole tree) on Windows. Safe at any time, including while `wait()` is
   * pending; a no-op once the child has been reaped.
   */
  kill() {
    this.#native.kill()
  }
}

/** A reusable, pre-initialized sandbox. */
export class Sandbox {
  #native

  /** @private — obtain instances through `Sandbox.build()`. */
  constructor(native) {
    this.#native = native
  }

  /**
   * Create a sandbox and pre-initialize platform policy state off the event
   * loop.
   */
  static async build(options) {
    return new Sandbox(await NativeSandbox.build(options))
  }

  /** Spawn `command` (with `args`) inside this sandbox. */
  spawn(command, args, options) {
    return new SandboxChild(this.#native.spawn(command, args, options), options)
  }
}

/** Spawn `command` (with `args`) confined by one-shot `options`. */
export function spawn(command, args, options) {
  return new SandboxChild(nativeSpawn(command, args, options), options)
}

// One native read is in flight per stream at a time: Readable does not call
// _read again before a push, and each _read issues exactly one readChunk.
// A `null` chunk pushes end-of-stream.
function makeReadable(readChunk) {
  return new Readable({
    read() {
      readChunk().then(
        (chunk) => this.push(chunk),
        (err) => this.destroy(err),
      )
    },
  })
}

function makeStdinWritable(native) {
  return new Writable({
    write(chunk, _encoding, callback) {
      const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
      native.writeStdin(data).then(() => callback(), callback)
    },
    final(callback) {
      native.endStdin().then(() => callback(), callback)
    },
    destroy(err, callback) {
      // Close the pipe on destroy too, so the child sees EOF.
      native.endStdin().then(
        () => callback(err),
        () => callback(err),
      )
    },
  })
}
