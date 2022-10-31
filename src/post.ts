import * as core from '@actions/core';
import * as fs from 'fs';
import * as exec from '@actions/exec';


async function run() {
    await exec.exec('ps aux');
}

run().catch((error) => core.setFailed(error.message));