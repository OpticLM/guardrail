// Public API of @opticlm/guardrail.
//
// The generated binding exposes promise primitives for piped standard streams.
// This facade composes only those primitives into ordinary Node streams and
// otherwise forwards the binding's complete public surface unchanged.

import { Readable, Writable } from 'node:stream'

import * as binding from './binding'

export * from './binding'

declare const __GUARDRAIL_CJS__: boolean

let wrapSandboxChild: (
  native: binding.SandboxChild,
  launch?: binding.SandboxSpawnOptions | null,
) => SandboxChild

/**
 * Handle to a spawned, sandboxed child process.
 *
 * `stdin`, `stdout`, and `stderr` are Node streams for the standard streams
 * spawned with `'pipe'`, and `null` otherwise.
 */
export class SandboxChild {
  readonly stdin: Writable | null
  readonly stdout: Readable | null
  readonly stderr: Readable | null

  readonly #native: binding.SandboxChild
  #exit?: Promise<binding.ExitResult>

  private constructor(native: binding.SandboxChild, launch?: binding.SandboxSpawnOptions | null) {
    this.#native = native
    this.stdin = launch?.stdin === 'pipe' ? makeStdinWritable(native) : null
    this.stdout = launch?.stdout === 'pipe' ? makeReadable(() => native.readStdout()) : null
    this.stderr = launch?.stderr === 'pipe' ? makeReadable(() => native.readStderr()) : null
  }

  /** OS process id of the child. */
  get pid(): number {
    return this.#native.pid
  }

  /**
   * Resolve with the child's `ExitResult` once it exits. Memoized: every call
   * returns the same promise, so it can be awaited any number of times.
   */
  wait(): Promise<binding.ExitResult> {
    this.#exit ??= this.#native.wait()
    return this.#exit
  }

  /**
   * Kill the child immediately: SIGKILL on Unix, Job Object termination (the
   * whole tree) on Windows. Safe at any time, including while `wait()` is
   * pending; a no-op once the child has been reaped.
   */
  kill(): void {
    this.#native.kill()
  }

  static {
    wrapSandboxChild = (native, launch) => new SandboxChild(native, launch)
  }
}

/** A reusable, pre-initialized sandbox. */
export class Sandbox {
  readonly #native: binding.Sandbox

  private constructor(native: binding.Sandbox) {
    this.#native = native
  }

  /** Create a sandbox and pre-initialize platform policy state off the event loop. */
  static async build(options?: binding.SandboxOptions | null): Promise<Sandbox> {
    return new Sandbox(await binding.Sandbox.build(options))
  }

  /** Spawn `command` (with `args`) inside this sandbox. */
  spawn(
    command: string,
    args?: Array<string> | null,
    options?: binding.SandboxSpawnOptions | null,
  ): SandboxChild {
    return wrapSandboxChild(this.#native.spawn(command, args, options), options)
  }
}

/** Spawn `command` (with `args`) confined by one-shot `options`. */
export function spawn(
  command: string,
  args?: Array<string> | null,
  options?: binding.SpawnOptions | null,
): SandboxChild {
  return wrapSandboxChild(binding.spawn(command, args, options), options)
}

function makeReadable(readChunk: () => Promise<Buffer | null>): Readable {
  return new Readable({
    read() {
      readChunk().then(
        (chunk) => this.push(chunk),
        (error) => this.destroy(error),
      )
    },
  })
}

function makeStdinWritable(native: binding.SandboxChild): Writable {
  return new Writable({
    write(chunk, _encoding, callback) {
      const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
      native.writeStdin(data).then(() => callback(), callback)
    },
    final(callback) {
      native.endStdin().then(() => callback(), callback)
    },
    destroy(error, callback) {
      // Close the pipe on destroy too, so the child sees EOF.
      native.endStdin().then(
        () => callback(error),
        () => callback(error),
      )
    },
  })
}

// napi's CommonJS loader determines its exports at runtime, so Rolldown cannot
// enumerate them for `export *`. Copy that generated surface without naming it;
// tsdown's explicit facade exports then shadow the three wrapped values.
if (__GUARDRAIL_CJS__) {
  Object.assign(exports, binding)
  delete exports.default
}
