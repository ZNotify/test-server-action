import * as core from '@actions/core';
import * as fs from 'fs';
import waitPort from 'wait-port';
import { timeout } from './util';

async function run() {
    const path = core.getState('tempPath');

    if (path) {
        // read log
        const logPath = 'data/app.log';
        // check log file
        if (!fs.existsSync(logPath)) {
            core.warning('Log file not found');
        } else {
            const log = await fs.promises.readFile(logPath, 'utf-8');
            core.summary.addHeading('Server log', 4);
            core.summary.addDetails("log", `<pre>${log}</pre>`)
            core.summary.write();
        }
    }

    const result = await waitPort({ host: 'localhost', port: 14444 });
    if (!result.open) {
        core.setFailed('Server panic during test');
    }
}

run().catch((error) => core.setFailed(error.message));
timeout();