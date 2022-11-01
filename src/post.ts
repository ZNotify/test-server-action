import * as core from '@actions/core';
import * as fs from 'fs';
import waitPort from 'wait-port';

async function run() {
    const path = core.getState('tempPath');

    if (path) {
        // read log
        const logPath = 'data/app.log';
        const log = await fs.promises.readFile(logPath, 'utf-8');
        core.summary.addHeading('Server log');
        core.summary.addCodeBlock(log, 'log');
        core.summary.write();
    }

    const result = await waitPort({ host: 'localhost', port: 14444 });
    if(!result.open){
        core.setFailed('Server panic during test');
    }
}

run().catch((error) => core.setFailed(error.message));