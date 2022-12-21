import * as core from '@actions/core';
import * as artifact from '@actions/artifact';
import * as fs from 'fs';
import * as exec from '@actions/exec';
import { spawn } from 'child_process';
import axios from 'axios';
import waitPort from 'wait-port';
import fetch from 'node-fetch';
// @ts-ignore
import sourceMapSupport from 'source-map-support'

sourceMapSupport.install()

const artifactClient = artifact.create();

type OS = 'Linux' | 'macOS' | 'Windows';

function getFilename(url: string) {
    return url.split('/').pop()!;
}

const assetMap: { [key in OS]: string } = {
    "Linux": "https://github.com/ZNotify/server/releases/download/latest/test-server-linux",
    "Windows": "https://github.com/ZNotify/server/releases/download/latest/test-server-windows.exe",
    "macOS": "https://github.com/ZNotify/server/releases/download/latest/test-server-macos"
}

const runnerOS = process.env['RUNNER_OS'] as OS;

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

    const ret = await waitPort({ host: 'localhost', port: 14444 })
    if (!ret.open) {
        core.setFailed('Server failed to start');
    }

    if (runnerOS === 'Windows') {
        // Windows is too slow to start server
        core.info('Waiting for server to be ready');
        await fetch('http://localhost:14444/alive');
        core.info('Server is ready');
    }

    core.endGroup();
}

async function execBinary(path: string) {
    core.startGroup('Executing binary');
    const filename = getFilename(assetMap[runnerOS]);
    const execPath = path + '/' + filename;

    // const sub = spawn(execPath, [], {
    //     detached: true,
    //     stdio: 'ignore',
    //     windowsHide: true,
    // })

    // const pid = sub.pid;
    // core.info(`Spawned process with PID ${pid}`);
    // core.saveState('pid', pid?.toString() ?? '');

    // sub.unref();
    exec.exec(execPath);

    core.endGroup();
}

async function downloadRelease(path: string) {
    core.startGroup('Downloading release');
    const downloadURL = assetMap[runnerOS as OS];
    const filename = getFilename(downloadURL);
    const downloadPath = path + '/' + filename;

    const writer = fs.createWriteStream(downloadPath);

    const resp = await axios.get(downloadURL, {
        responseType: 'stream'
    })

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
        const downloadResponse = await artifactClient.downloadArtifact('test-server', path, {
            createArtifactFolder: false
        });
        core.info(`Artifact ${downloadResponse.artifactName} exists.`);
        core.endGroup();
        return true;
    } catch (error) {
        core.info('Artifact may not exist, downloading from release');
        core.endGroup();
        return false;
    }
}

async function tryGrantPermission(path: string) {
    const filename = getFilename(assetMap[runnerOS]);
    core.startGroup('Granting permission');
    if (runnerOS === 'Linux') {
        core.startGroup('Granting permission');
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

run().catch(error => core.setFailed(error.message));

