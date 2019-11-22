'use strict';

// node core

// third-party

// internal

module.exports = {
  parserOptions: {
    sourceType: 'script',
    ecmaFeatures: {
      jsx: false,
    },
  },
  env: {
    jest: true,
    node: true,
  },
  plugins: ['prettier'],
  extends: ['airbnb-base', 'prettier'],
  rules: {
    strict: ['error', 'safe'],
    'prettier/prettier': 'error',
    // disallow dangling underscores in identifiers
    // https://eslint.org/docs/rules/no-underscore-dangle
    'no-underscore-dangle': [
      'error',
      {
        allow: ['_id'],
        allowAfterThis: false,
        allowAfterSuper: false,
        enforceInMethodNames: true,
      },
    ],
  },
  overrides: [
    {
      files: ['ava.config.js', '**/*.test.js'],
      parserOptions: {
        ecmaVersion: 2017,
        sourceType: 'module',
      },
      extends: 'plugin:ava/recommended',
      plugins: ['ava'],

      rules: {
        'import/no-extraneous-dependencies': [
          'error',
          { devDependencies: true },
        ],
      },
    },
  ],
};
