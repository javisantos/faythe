import resolve from '@rollup/plugin-node-resolve'
import commonjs from '@rollup/plugin-commonjs'
import nodePolyfills from 'rollup-plugin-node-polyfills'
import replace from '@rollup/plugin-replace'
import json from '@rollup/plugin-json'
import { terser } from 'rollup-plugin-terser'

export default [
  {
    input: 'main.js',
    output: [
      {
        file: 'dist/faythe.js',
        format: 'esm'
      }],
    plugins: [
      json(),
      commonjs(),
      resolve({
        preferBuiltins: true,
        browser: true
      }),
      nodePolyfills(),

      replace({ 'process.browser': !!process.env.BROWSER }),
      terser()
    ]
  }
]
