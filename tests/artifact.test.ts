import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ArtifactClient, downloadCurrentArtifact } from '../src/artifact';

for (const required of [false, true]) {
    test(`downloads the current-run artifact by ID (required=${required})`, async () => {
        const calls: unknown[] = [];
        const client: ArtifactClient = {
            async getArtifact(name) {
                calls.push(['get', name]);
                return { artifact: { id: 123, name } };
            },
            async downloadArtifact(id, options) {
                calls.push(['download', id, options]);
                return { downloadPath: options.path };
            },
        };
        assert.equal(await downloadCurrentArtifact(client, 'server-linux', '/tmp/server', required), true);
        assert.deepEqual(calls, [
            ['get', 'server-linux'],
            ['download', 123, { path: '/tmp/server' }],
        ]);
    });
}

for (const stage of ['lookup', 'download']) {
    for (const required of [false, true]) {
        test(`${stage} failure ${required ? 'rejects strict mode' : 'preserves release fallback'}`, async () => {
            const client: ArtifactClient = {
                async getArtifact(name) {
                    if (stage === 'lookup') throw new Error('artifact missing');
                    return { artifact: { id: 123, name } };
                },
                async downloadArtifact() {
                    throw new Error('download failed');
                },
            };
            const result = downloadCurrentArtifact(client, 'server-linux', '/tmp/server', required);
            if (required) {
                await assert.rejects(result, /Required current-run artifact server-linux could not be downloaded/);
            } else {
                assert.equal(await result, false);
            }
        });
    }
}
