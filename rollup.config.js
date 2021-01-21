import resolve from '@rollup/plugin-node-resolve'
import commonjs from '@rollup/plugin-commonjs'
import nodePolyfills from 'rollup-plugin-node-polyfills'
// import builtins from 'rollup-plugin-node-polyfills'
// import replace from '@rollup/plugin-replace'
import json from '@rollup/plugin-json'
import globals from 'rollup-plugin-node-globals'
import { terser } from 'rollup-plugin-terser'
import alias from 'rollup-plugin-alias'
import { compress } from 'brotli'
import gzipPlugin from 'rollup-plugin-gzip'
import path from 'path'

export default [
  {
    input: 'main.js',
    output: [
      {
        file: 'dist/faythe.js',
        format: 'esm'
      }],
    plugins: [
      alias({
        entries: [
          { find: './_wordlists', replacement: path.join(__dirname, 'bip39-english.js') }
        ]
      }),
      json(),
      commonjs(),
      // builtins(),
      resolve({
        preferBuiltins: false,
        browser: true
      }),
      globals(),
      nodePolyfills(),
      terser({
        output: {
          comments: false
        },
        compress: {
          passes: 2,
          ecma: 6,
          toplevel: true,
          keep_infinity: true,
          module: true
        },
        mangle: false
        // mangle: {
        //   properties: {
        //     regex: /^_/
        //   }
        // }
      }),
      gzipPlugin({
        customCompression: content => compress(Buffer.from(content)),
        fileName: () => 'faythe.br'
      })
    ]
  }
]
