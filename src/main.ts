import * as core from '@actions/core';
import * as artifact from '@actions/artifact';
import * as fs from 'fs';
import * as exec from '@actions/exec';
import { spawn } from 'child_process';
import * as https from 'https';

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
    await tryGrantPermission(tempPath);
    await execBinary(tempPath);
}

async function execBinary(path: string) {
    core.startGroup('Executing binary');
    const filename = getFilename(assetMap[runnerOS as OS]);
    const execPath = path + '/' + filename;
    const sub = spawn(execPath, ["--test"], {
        detached: true,
        stdio: 'ignore'
    })
    sub.unref();
    core.endGroup();
}

async function downloadRelease(path: string) {
    core.startGroup('Downloading release');
    const downloadURL = assetMap[runnerOS as OS];
    const filename = getFilename(downloadURL);
    const downloadPath = path + '/' + filename;
    
    await new Promise<void>((resolve, reject) => {
        https.get(downloadURL, (res) => {
            const fileStream = fs.createWriteStream(downloadPath);
            res.pipe(fileStream);
            fileStream.on('finish', () => {
                fileStream.close();
                resolve();
            });
        })
    })

    core.info('Downloaded release to ' + downloadPath);
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

async function tryGrantPermission(path:string) {
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

