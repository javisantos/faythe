module.exports = {
  env: {
    browser: true,
    node: true
  },
  extends: [
    'standard'
  ],
  globals: {
    Atomics: 'readonly',
    SharedArrayBuffer: 'readonly'
  },
  parserOptions: {
    ecmaVersion: 2020,
    sourceType: 'module',
    exclude: [
      './dist'
    ]
  },
  rules: {
  },
  plugins: [
    'html'
  ]
}
