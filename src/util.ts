import * as core from '@actions/core';

export function timeout() {
    const exit = () => {
        core.setFailed('Timeout after 2s');
        process.exit(1);
    }
    setTimeout(exit, 20 * 1000);
}