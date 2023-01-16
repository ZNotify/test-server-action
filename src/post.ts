import * as core from '@actions/core';
import * as fs from 'fs';
import * as path from 'path';
import waitPort from 'wait-port';
import { cancelTimeout, startTimeout } from './util';

async function log() {
    core.startGroup("Writing log")
    const tmpPath = core.getState('tempPath');
    // read log
    const logPath = path.join(tmpPath, 'data/app.log');
    // check log file

    if (!fs.existsSync(logPath)) {
        core.warning('Log file not found');
    } else {
        const log = await fs.promises.readFile(logPath, 'utf-8');
        core.summary.addHeading('Server log', 3);
        core.summary.addDetails("log", `<pre>${log}</pre>`)
        await core.summary.write();
        core.info('Log written');
    }
    core.endGroup();
}

async function clean() {
    core.startGroup("Cleaning");

    const result = await waitPort({ host: 'localhost', port: 14444, timeout: 10 * 1000, output: 'silent' });
    if (!result.open) {
        core.setFailed('Server panic during test');
    } else {
        const pid = Number(core.getState('pid'));
        core.info(`Killing process ${pid}`);
        process.kill(pid);
    }

    core.endGroup();
}

async function run() {
    await log();
    await clean();
}

startTimeout();
run().catch((error) => {
    core.setFailed(error.message);
    cancelTimeout();
}).then(() => {
    cancelTimeout();
});
