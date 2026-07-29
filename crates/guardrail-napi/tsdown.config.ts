import { fileURLToPath } from 'node:url'

import { defineConfig } from 'tsdown'

const bindingMjs = fileURLToPath(new URL('./binding.mjs', import.meta.url))
const bindingCjs = fileURLToPath(new URL('./binding.cjs', import.meta.url))

export default defineConfig([
  {
    name: 'esm',
    entry: 'index.ts',
    format: 'esm',
    minify: true,
    platform: 'node',
    outDir: '.',
    clean: false,
    deps: { neverBundle: [/\.node$/] },
    alias: { './binding': bindingMjs },
    define: { __GUARDRAIL_CJS__: 'false' },
    dts: true,
    outExtensions: () => ({ js: '.mjs', dts: '.d.ts' }),
  },
  {
    name: 'cjs',
    entry: 'index.ts',
    format: 'cjs',
    minify: true,
    platform: 'node',
    outDir: '.',
    clean: false,
    deps: { neverBundle: [/\.node$/] },
    alias: { './binding': bindingCjs },
    define: { __GUARDRAIL_CJS__: 'true' },
    dts: false,
    outExtensions: () => ({ js: '.cjs' }),
  },
])
