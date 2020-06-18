import resolve from '@rollup/plugin-node-resolve'
import commonjs from '@rollup/plugin-commonjs'
import nodePolyfills from 'rollup-plugin-node-polyfills'
import replace from '@rollup/plugin-replace'
import { terser } from 'rollup-plugin-terser'
import pkg from './package.json'

export default [
  {
    input: 'main.js',
    output: [
      {
        file: pkg.browser,
        format: 'es'
      }],
    plugins: [
      commonjs(),
      resolve({
        preferBuiltins: false,
        browser: true,
        jsnext: true,
        main: true
      }),
      nodePolyfills({
        buffer: false
      }),

      replace({ 'process.browser': !!process.env.BROWSER }),
      terser()
    ]
  }
]
