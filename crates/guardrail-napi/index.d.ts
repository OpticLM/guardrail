import type { Readable, Writable } from 'node:stream'

import type { ExitResult, SandboxOptions, SandboxSpawnOptions, SpawnOptions } from './binding.js'

export type {
  ExitResult,
  FsAccess,
  FsAccessKind,
  NetworkPolicy,
  SandboxOptions,
  SandboxSpawnOptions,
  SpawnOptions,
  StdioMode,
  UserNamespacePolicy,
} from './binding.js'

export { cleanupWindowsNamespace, probeSupport, windowsHostSetupConfigured } from './binding.js'

/**
 * Handle to a spawned, sandboxed child process.
 *
 * `stdin`, `stdout`, and `stderr` are Node streams for the standard streams
 * spawned with `'pipe'`, and `null` otherwise.
 */
export declare class SandboxChild {
  /** Writable connected to the child's piped stdin, or `null`. */
  readonly stdin: Writable | null
  /** Readable connected to the child's piped stdout, or `null`. */
  readonly stdout: Readable | null
  /** Readable connected to the child's piped stderr, or `null`. */
  readonly stderr: Readable | null
  /** OS process id of the child. */
  get pid(): number
  /**
   * Resolve with the child's `ExitResult` once it exits. Memoized: every call
   * returns the same promise, so it can be awaited any number of times (e.g.
   * once at spawn to monitor a persistent child, again at shutdown). Exit
   * status only — piped output is read from the streams.
   */
  wait(): Promise<ExitResult>
  /**
   * Kill the child immediately: SIGKILL on Unix, Job Object termination (the
   * whole tree) on Windows. Safe at any time, including while `wait()` is
   * pending; a no-op once the child has been reaped.
   */
  kill(): void
  private constructor()
}

/** A reusable, pre-initialized sandbox. */
export declare class Sandbox {
  /**
   * Create a sandbox and pre-initialize platform policy state off the event
   * loop.
   */
  static build(options?: SandboxOptions | undefined | null): Promise<Sandbox>
  /** Spawn `command` (with `args`) inside this sandbox. */
  spawn(
    command: string,
    args?: Array<string> | undefined | null,
    options?: SandboxSpawnOptions | undefined | null,
  ): SandboxChild
  private constructor()
}

/**
 * Spawn `command` (with `args`) confined by `options`. Each standard stream
 * follows its configured disposition — inherited from the parent process by
 * default; every other parent file descriptor or handle is kept out of the
 * child. Returns a handle to await or kill the child, with Node streams
 * attached for piped stdio.
 */
export declare function spawn(
  command: string,
  args?: Array<string> | undefined | null,
  options?: SpawnOptions | undefined | null,
): SandboxChild
