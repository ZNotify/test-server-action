import * as core from '@actions/core';

const timeoutLimit = 60 * 10;

function exit() {
    core.setFailed(`Timeout after ${timeoutLimit}s`);
    process.exit(1);
}

let timer: NodeJS.Timeout

export function startTimeout() {
    timer = setTimeout(exit, timeoutLimit * 1000);
}

export function cancelTimeout() {
    clearTimeout(timer);
}


type OS = 'Linux' | 'macOS' | 'Windows';
export const runnerOS = process.env['RUNNER_OS'] as OS;

type Resource = {
    url: string,
    filename: string
    artifactName: string
}

const resources: { [key in OS]: Resource } = {
    'Linux': {
        artifactName: 'server-linux',
        filename: 'test-server-linux',
        url: 'https://github.com/ZNotify/server/releases/download/test/test-server-linux'
    },
    'Windows': {
        artifactName: 'server-windows',
        filename: 'test-server-windows.exe',
        url: 'https://github.com/ZNotify/server/releases/download/test/test-server-windows.exe'
    },
    'macOS': {
        artifactName: 'server-macos',
        filename: 'test-server-macos',
        url: 'https://github.com/ZNotify/server/releases/download/test/test-server-macos'
    }
}

export const currentResource = resources[runnerOS];