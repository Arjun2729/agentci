import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov', 'json-summary'],
      reportsDirectory: './coverage',
      include: ['src/**/*.ts'],
      exclude: [
        'src/**/*.test.ts',
        'src/cli/**',
        'src/dashboard/**',
        'src/report/**',
        // Patches are tested via integration tests in spawned subprocesses;
        // V8 coverage can't measure subprocess coverage.
        'src/recorder/patches/**',
        'src/recorder/register.ts',
        'src/adapters/**',
        // Pure type definitions — no runtime code to cover.
        'src/core/types.ts',
        // Re-export barrel files with no logic.
        'src/pro/index.ts',
        // Alpha placeholder — throws on every call, tested by license gate tests.
        'src/pro/similarity/annpack.ts',
        // HTTP client for remote server — tested via integration tests in remote.test.ts.
        'src/pro/remote/client.ts',
        // Runtime context and enforcement — only execute inside spawned subprocesses;
        // V8 coverage can't measure subprocess coverage.
        'src/recorder/context.ts',
        'src/recorder/enforce.ts',
      ],
      thresholds: {
        lines: 70,
        functions: 70,
        branches: 50,
        statements: 70,
      },
    },
  },
});
