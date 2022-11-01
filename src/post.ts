import * as core from '@actions/core';
import * as fs from 'fs';

async function run() {
    const path = core.getState('tempPath');

    if (path) {
        // read log
        const logPath = 'data/app.log';
        const log = await fs.promises.readFile(logPath, 'utf-8');
        core.summary.addHeading('Server log');
        core.summary.addBreak();
        core.summary.addCodeBlock(log, 'log');
        core.summary.write();
    }
}

run().catch((error) => core.setFailed(error.message));