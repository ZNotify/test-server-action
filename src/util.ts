import * as core from '@actions/core';

function exit() {
    core.setFailed('Timeout after 20s');
    process.exit(1);
}

const timer = setTimeout(exit, 20 * 1000);

export function cancelTimeout() {
    clearTimeout(timer);
}

