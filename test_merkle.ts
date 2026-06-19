// test_merkle.ts - Execut  test diagnóstic of Merkle tree & proof geration
import initWasm, { compute_poseidon_native, client_generate_proof } from './pkg/identifi_core.js';
import * as fs from 'fs';

interface LeafInput {
    master: string;
    sub: string;
}


interface MerklePath {
    path_elements: string[];
    path_indices: number[];
}

function padHex(n: bigint): string {
    let s = n.toString(16);
    if (s.length > 64) s = s.slice(-64);
    return '0x' + s.padStart(64, '0');
}

async function poseidon(a: string, b: string): Promise<string> {
    return await compute_poseidon_native(a, b);
}

async function buildTree(leaves: string[]): Promise<string[][]> {
    const levels: string[][] = [leaves];
    let cur = leaves;
    while (cur.length > 1) {
        const next: string[] = [];
        for (let i = 0; i < cur.length; i += 2) {
            const left = cur[i];
            const right = (i + 1 < cur.length) ? cur[i + 1] : cur[i];
            const node = await poseidon(left, right);
            next.push(node);
        }
        levels.push(next);
        cur = next;
    }
    return levels;
}

function merklePathForIndex(levels: string[][], index: number): MerklePath {
    const depth = levels.length - 1;
    const path_elements: string[] = [];
    const path_indices: number[] = [];
    let idx = index;

    for (let lvl = 0; lvl < depth; lvl++) {
        const levelLength = levels[lvl].length;
        const isEven = (idx % 2 === 0);
        let siblingIndex = isEven ? idx + 1 : idx - 1;

        if (siblingIndex >= levelLength) {
            siblingIndex = idx;
        }

        const sibling = levels[lvl][siblingIndex];
        const isSiblingOnRight = isEven ? 1 : 0;

        path_elements.push(sibling);
        path_indices.push(isSiblingOnRight);
        idx = Math.floor(idx / 2);
    }
    return { path_elements, path_indices };
}

async function main(): Promise<void> {
    // 1. Read the .wasm file directly
    const wasmBuffer = fs.readFileSync('./pkg/identifi_core_bg.wasm');

    // 2. Pass the compiled buffer directly to the wasm-pack initializer
    await initWasm(wasmBuffer);

    const leavesInputs: LeafInput[] = [];
    for (let i = 0; i < 16; i++) {
        const master = padHex(BigInt(i + 1));
        const sub = padHex(BigInt((i + 1) * 1000));
        leavesInputs.push({ master, sub });
    }

    const leafHashes: string[] = [];
    for (const li of leavesInputs) {
        const h = await poseidon(li.master, li.sub);
        leafHashes.push(h);
    }

    const levels = await buildTree(leafHashes);
    const root = levels[levels.length - 1][0];
    console.log('Merkle root calculated:', root);

    const leafIndex = 5;
    const { path_elements, path_indices } = merklePathForIndex(levels, leafIndex);

    console.log('Path elements (strings hex):', path_elements);
    console.log('Path indices (0=left, 1=right):', path_indices);

    const chosen = leavesInputs[leafIndex];
    const masterHex = chosen.master;
    const subHex = chosen.sub;

    // 3. Timestamps converted cleanly to BigInt using 'n' suffix
    const iat: bigint = BigInt(Math.floor(Date.now() / 1000) - 60);
    const exp: bigint = iat + 3600n;

    const pkHex = fs.readFileSync('./proving_key.hex', 'utf8').trim();

    try {
        const proofHex: string = client_generate_proof(
            masterHex,
            subHex,
            root,
            iat,
            exp,
            path_elements,
            new Uint8Array(path_indices),
            pkHex
        );
        console.log('\n--- PROOF GENERATED SUCCESSFULLY ---');
        console.log('Proof hex:', proofHex);
    } catch (err) {
        console.error('Error generating ZK Proof:', err);
    }
}

main().catch(e => console.error(e));