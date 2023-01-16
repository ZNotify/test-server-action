import * as core from '@actions/core';
import * as artifact from '@actions/artifact';
import * as fs from 'fs';
import * as exec from '@actions/exec';
import { spawn } from 'child_process';
import * as path from 'path';
import axios from 'axios';
import waitPort from 'wait-port';
import fetch from 'node-fetch';
import { cancelTimeout, currentResource, runnerOS, startTimeout } from './util';

const artifactClient = artifact.create();

const res = currentResource;


async function run() {
    const tempPath = await fs.promises.mkdtemp('server');
    core.saveState('tempPath', tempPath);

    const da = await downloadArifact(tempPath);
    if (!da) {
        await downloadRelease(tempPath);
    }
    await tryGrantPermission(tempPath);
    await execBinary(tempPath);
    await wait();
}

async function wait() {
    core.startGroup('Waiting server up');

    const ret = await waitPort({ host: 'localhost', port: 14444, timeout: 1000 * 5, output: 'silent' })
    if (!ret.open) {
        core.setFailed('Server failed to start');
    } else {
        core.info('Server is up');
    }

    if (runnerOS === 'Windows') {
        // Windows is too slow to start server
        core.info('Windows additional waiting');
        await fetch('http://localhost:14444/alive');
        core.info('Windows additional waiting done');
    }

    core.endGroup();
}

async function execBinary(tmpDir: string) {
    core.startGroup('Executing binary');

    const execPath = path.join(tmpDir, res.filename);

    const sub = spawn(execPath, [], {
        detached: true,
        stdio: 'ignore',
        windowsHide: true,
    })

    const pid = sub.pid;
    core.info(`Working directory: ${tmpDir}`)
    core.info(`Executed binary: ${execPath}`)
    core.info(`Spawned process with PID ${pid}`);
    core.saveState('pid', pid?.toString() ?? '');

    sub.unref();

    core.endGroup();
}

async function downloadRelease(tmpDir: string) {
    core.startGroup('Downloading release');
    const downloadPath = path.join(tmpDir, res.filename);

    const writer = fs.createWriteStream(downloadPath);

    const resp = await axios.get(res.url, {
        responseType: 'stream'
    })

    if (resp.status !== 200) {
        core.setFailed(`Failed to download release, status: ${resp.status} ${resp.statusText}`);
        return;
    }

    await new Promise<void>((resolve, reject) => {
        resp.data.pipe(writer);
        let error: Error | null = null;
        writer.on('error', err => {
            error = err;
            core.setFailed(err.message);
            writer.close();
            reject(err);
        });
        writer.on('close', () => {
            if (!error) {
                core.info('Downloaded release to ' + downloadPath);
                resolve();
            }
        });
    })

    core.endGroup();
}

async function downloadArifact(path: string): Promise<Boolean> {
    core.startGroup('Downloading artifact');
    try {
        const downloadResponse = await artifactClient.downloadArtifact(res.artifactName, path, {
            createArtifactFolder: false
        });
        core.info(`Artifact ${downloadResponse.artifactName} exists. Downloaded to ${downloadResponse.downloadPath}`);
        core.endGroup();
        return true;
    } catch (error) {
        core.info('Artifact may not exist, downloading from release');
        core.endGroup();
        return false;
    }
}

async function tryGrantPermission(path: string) {
    const filename = res.filename;
    core.startGroup('Granting permission');
    if (runnerOS === 'Linux') {
        await exec.exec('chmod', ['+x', `${path}/${filename}`]);
        core.info('Granted permission to ' + filename);
    } else if (runnerOS === 'macOS') {
        await exec.exec('chmod', ['+x', `${path}/${filename}`]);
        core.info('Granted permission to ' + filename);
    } else {
        core.info('No need to grant permission');
    }
    core.endGroup();
}

startTimeout();
run().catch((error) => {
    core.setFailed(error.message);
    cancelTimeout();
}).then(() => {
    cancelTimeout();
});

