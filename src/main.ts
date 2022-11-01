import * as core from '@actions/core';
import * as artifact from '@actions/artifact';
import * as fs from 'fs';
import * as exec from '@actions/exec';
import { spawn } from 'child_process';
import axios from 'axios';
import waitPort from 'wait-port';
// @ts-ignore
import sourceMapSupport from 'source-map-support'

sourceMapSupport.install()

const artifactClient = artifact.create();

type OS = 'Linux' | 'macOS' | 'Windows';

function getFilename(url: string) {
    return url.split('/').pop()!;
}

const assetMap: { [key: string]: string } = {
    "Linux": "https://github.com/ZNotify/server/releases/download/latest/server-linux",
    "Windows": "https://github.com/ZNotify/server/releases/download/latest/server-windows.exe",
    "macOS": "https://github.com/ZNotify/server/releases/download/latest/server-macos"
}

const runnerOS = process.env['RUNNER_OS'];

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
    const time = Date.now();

    const ret = await waitPort({ host: 'localhost', port: 14444 })
    if (!ret.open) {
        core.setFailed('Server failed to start');
    }

    core.endGroup();
}

async function execBinary(path: string) {
    core.startGroup('Executing binary');
    const filename = getFilename(assetMap[runnerOS as OS]);
    const execPath = path + '/' + filename;

    const sub = spawn(execPath, ["--test"], {
        detached: true,
        stdio: 'ignore',
        windowsHide: true,
        cwd: path
    })

    const pid = sub.pid;
    core.info(`Spawned process with PID ${pid}`);
    core.saveState('pid', pid?.toString() ?? '');

    sub.unref();

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
        const downloadResponse = await artifactClient.downloadArtifact('server', path, {
            createArtifactFolder: false
        });
        core.info(`Artifact ${downloadResponse.artifactName} exists.`);
        return true;
    } catch (error) {
        core.info('Artifact may not exist, downloading from release');
        return false;
    }
    core.endGroup();
}

async function tryGrantPermission(path: string) {
    if (runnerOS === 'Linux') {
        core.startGroup('Granting permission');
        await exec.exec('chmod', ['+x', `${path}/server-linux`]);
        core.endGroup();
    } else if (runnerOS === 'macOS') {
        core.startGroup('Granting permission');
        await exec.exec('chmod', ['+x', `${path}/server-macos`]);
        core.endGroup();
    }
}

run().catch(error => core.setFailed(error.message));

