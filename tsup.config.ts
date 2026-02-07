import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    'cli/main': 'src/cli/main.ts',
    'recorder/register': 'src/recorder/register.ts',
    'adapters/openclaw': 'src/adapters/openclaw.ts'
  },
  format: ['cjs'],
  outDir: 'dist',
  dts: false,
  splitting: false,
  sourcemap: true,
  clean: true,
  target: 'node18'
});
