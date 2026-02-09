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
