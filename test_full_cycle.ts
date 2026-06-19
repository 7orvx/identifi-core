// test_full_cycle.ts - Executing the cryptographic verification test of the V2     
import initWasm, {
    compute_poseidon_native,
    client_generate_proof,
    client_verify_proof
} from './pkg/identifi_core.js';
import * as fs from 'fs';

// type leaf input    
interface LeafInput {
    master: string;
    sub: string;
}

// Ttype return path 
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
    // performance timers
    console.time('Total cycle time');

    const wasmBuffer = fs.readFileSync('./pkg/identifi_core_bg.wasm');
    await initWasm(wasmBuffer);

    console.log("1. Generating Merkle Tree (local)...");
    console.time('-> Time of the Merkle Tree');

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
    console.log('   Merkle root:', root);
    console.timeEnd('-> Time of the Merkle Tree');

    const leafIndex = 5;
    const { path_elements, path_indices } = merklePathForIndex(levels, leafIndex);

    const chosen = leavesInputs[leafIndex];
    const masterHex = chosen.master;
    const subHex = chosen.sub;

    const iat: bigint = BigInt(Math.floor(Date.now() / 1000) - 60);
    const exp: bigint = iat + 3600n;

    console.log("\n2. Generating ZK Proof (Client side)...");
    console.time('-> Time of the Proof (Prover)');
    const pkHex = fs.readFileSync('./proving_key.hex', 'utf8').trim();

    let proofHex: string;
    try {
        // TypeScript path_elements (string[]) map to Box<[JsValue]> 
        // Uint8Array map to Box<[u8]> 
        proofHex = client_generate_proof(
            masterHex,
            subHex,
            root,
            iat,
            exp,
            path_elements,
            new Uint8Array(path_indices),
            pkHex
        );
        console.log('   Proof cryptographic computed successfully!');
    } catch (err) {
        console.error('Error in the generation of the Proof:', err);
        return;
    }
    console.timeEnd('-> Time of the Proof (Prover)');

    console.log("\n3. Sending the Proof to the Auditor (Verification side)...");
    console.time('-> Verification Time (Verifier)');
    const vkHex = fs.readFileSync('./verifying_key.hex', 'utf8').trim();

    try {
        const isValid: boolean = client_verify_proof(
            proofHex,
            root,
            iat,
            exp,
            vkHex
        );

        console.log('\n--- FINAL RESULT OF THE AUDIT ---');
        if (isValid) {
            console.log('✅ EXCELLENT: Proof 100% Valid in the Groth16 Circuit!');
        } else {
            console.log('❌ FAILURE: Parameters refused by the verifier.');
        }
    } catch (err) {
        console.error('Critical Error in the Verifier:', err);
    }
    console.timeEnd('-> Verification Time (Verifier)');

    console.log("\n------------------------------------");
    console.timeEnd('Total cycle time');
}

main().catch(e => console.error(e));