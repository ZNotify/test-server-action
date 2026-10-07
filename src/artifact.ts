import * as core from '@actions/core';

export interface ArtifactClient {
    getArtifact(name: string): Promise<{ artifact: { id: number; name: string } }>;
    downloadArtifact(id: number, options: { path: string }): Promise<{ downloadPath?: string }>;
}

export async function downloadCurrentArtifact(
    client: ArtifactClient,
    name: string,
    path: string,
    required: boolean,
): Promise<boolean> {
    core.startGroup('Downloading artifact');
    try {
        const { artifact } = await client.getArtifact(name);
        const result = await client.downloadArtifact(artifact.id, { path });
        core.info(`Current-run artifact ${artifact.name} (${artifact.id}) downloaded to ${result.downloadPath}`);
        return true;
    } catch (error) {
        if (required) {
            throw new Error(`Required current-run artifact ${name} could not be downloaded: ${String(error)}`);
        }
        core.info('Artifact may not exist, downloading from release');
        return false;
    } finally {
        core.endGroup();
    }
}
