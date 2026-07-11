// ESLint 9 flat config for signalis-core.
//
// ESLint v9 dropped support for `.eslintrc.*` files — this is the new
// "flat config" format. It uses the @typescript-eslint packages that are
// already in devDependencies (parser + plugin), so no new installs needed.
//
// Docs: https://eslint.org/docs/latest/use/configure/configuration-files

const tsParser = require('@typescript-eslint/parser');
const tsPlugin = require('@typescript-eslint/eslint-plugin');

// Safely pull the recommended ruleset from the plugin. Across @typescript-eslint
// v8.x the shape has been stable at `configs.recommended.rules`, but we guard
// against a missing structure so a plugin update can't break linting outright.
const recommendedRules =
  (tsPlugin.configs &&
    tsPlugin.configs.recommended &&
    tsPlugin.configs.recommended.rules) ||
  {};

module.exports = [
  // Ignore build output and generated files
  {
    ignores: [
      'dist/**',
      'target/**',
      'node_modules/**',
      'coverage/**',
      'index.js', // napi-generated
      'index.d.ts', // napi-generated
      '**/*.node',
      'npm/**', // per-platform sub-packages
      'examples/**',
    ],
  },

  // TypeScript source + tests
  {
    files: ['src/**/*.ts', '__tests__/**/*.ts'],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        ecmaVersion: 2022,
        sourceType: 'module',
      },
      globals: {
        // Node.js globals (since we can't rely on the `globals` package)
        Buffer: 'readonly',
        process: 'readonly',
        console: 'readonly',
        __dirname: 'readonly',
        __filename: 'readonly',
        module: 'writable',
        require: 'readonly',
        exports: 'writable',
        global: 'readonly',
        setTimeout: 'readonly',
        clearTimeout: 'readonly',
        setInterval: 'readonly',
        clearInterval: 'readonly',
        NodeJS: 'readonly',
      },
    },
    plugins: {
      '@typescript-eslint': tsPlugin,
    },
    rules: {
      // Base recommended rules from the TS plugin
      ...recommendedRules,

      // Project-specific tweaks
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/explicit-function-return-type': 'off',
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
      'no-console': 'off',
      'prefer-const': 'error',
      'no-var': 'error',
    },
  },

  // Test files: relax a couple of rules that are noisy in tests
  {
    files: ['__tests__/**/*.ts'],
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-non-null-assertion': 'off',
    },
  },
];
