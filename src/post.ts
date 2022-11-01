import * as core from '@actions/core';
import * as fs from 'fs';
import * as exec from '@actions/exec';


async function run() {
    const path = core.getState('tempPath');
    const pid = core.getState('pid');

    if (pid) {
        core.info(`Killing process with PID ${pid}`);
        await exec.exec('kill', [pid]);
    }

    if (path) {
        // read log
        const logPath = 'data/app.log';
        const log = await fs.promises.readFile(logPath, 'utf-8');
        core.summary.addCodeBlock(log, 'log');
    }
}

run().catch((error) => core.setFailed(error.message));