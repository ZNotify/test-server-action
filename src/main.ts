import * as core from '@actions/core';
import * as artifact from '@actions/artifact';
import * as fs from 'fs';
import * as exec from '@actions/exec';
import { spawn } from 'child_process';

const artifactClient = artifact.create();

type OS = 'Linux' | 'macOS' | 'Windows';

function getFilename(url: string) {
    return url.split('/').pop();
}

const assetMap: { [key: string]: string } = {
    "Linux": "https://github.com/ZNotify/server/releases/download/latest/server-linux",
    "Windows": "https://github.com/ZNotify/server/releases/download/latest/server-windows.exe",
    "macOS": "https://github.com/ZNotify/server/releases/download/latest/server-macos"
}

const runnerOS = process.env['RUNNER_OS'];

async function run() {
    const tempPath = await fs.promises.mkdtemp('server');
    const da = await downloadArifact(tempPath);
    if (!da) {
        await downloadRelease(tempPath);
    }
    await execBinary(tempPath);
}

async function execBinary(path: string) {
    core.startGroup('Executing binary');
    const filename = getFilename(assetMap[runnerOS as OS]);
    const execPath = path + '/' + filename;
    spawn(execPath, ["--test"], {
        detached: true,
    })
    core.endGroup();
}

async function downloadRelease(path: string) {
    core.startGroup('Downloading release');
    const downloadURL = assetMap[runnerOS as OS];
    const filename = getFilename(downloadURL);
    const downloadPath = path + '/' + filename;
    const resp = await fetch(downloadURL);
    if (!resp.ok) {
        core.setFailed('Failed to download release');
        throw new Error(`unexpected response ${resp.statusText}`);
    }
    const buffer = await resp.arrayBuffer();
    await fs.promises.writeFile(downloadPath, Buffer.from(buffer));
    core.info('Downloaded release to ' + downloadPath);
    core.endGroup();
}

async function downloadArifact(path: string): Promise<Boolean> {
    core.startGroup('Downloading artifact');
    try {
        artifactClient.downloadArtifact('server', path, {
            createArtifactFolder: false
        });
        return true;
    } catch (error) {
        core.info('Artifact may not exist, downloading from release');
        return false;
    }
    core.endGroup();
}

run().catch(error => core.setFailed(error.message));

