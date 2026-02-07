import fs from 'fs';
import { TraceWriter, RecorderState } from './writer';
import { PolicyConfig } from '../core/types';

export interface RecorderContext {
  runId: string;
  runDir: string;
  workspaceRoot: string;
  config: PolicyConfig;
  writer: TraceWriter;
  state: RecorderState;
  originals: {
    fs: typeof fs;
    appendFileSync: typeof fs.appendFileSync;
    writeFileSync: typeof fs.writeFileSync;
    mkdirSync: typeof fs.mkdirSync;
  };
}
