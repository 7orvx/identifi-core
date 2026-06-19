# IdentiFI Core (ZK-Engine)

The core cryptographic engine of the **IdentiFI Protocol**, a stateless, privacy-preserving authority layer built for Web3 and decentralized applications. This module features a high-performance ZK-SNARK circuit using Groth16, compiled natively from Rust to WebAssembly (WASM) to run blindingly fast client-side proving and local verification.

## 🚀 Quick Start / Running the Tests

To audit and validate the zero-knowledge proof generation and Merkle tree logic locally, you can run the benchmarking scripts using Node.js.

### Prerequisites
Make sure you have [Node.js](https://nodejs.org/) installed on your machine.

### Execution Commands
Run the following commands in your terminal from the root of the `identifi-core` directory:

1. Build the Rust cryptographic circuit into WebAssembly:
  ```bash
  wasm-pack build --target web

  ```

2. **Test the Full Cryptographic Cycle (Prover & Verifier):**
```bash
   npm run test:full

```

3. **Test the Local Merkle Tree Proof Generation:**

```bash
   npm run test:merkle

```

---
## 📊 Performance Benchmarks

Here is an example of the cryptographic cycle execution logs, showcasing the performance of the native Rust WASM circuit running locally:

```bash
> identifi-core@2.0.0 test:full
> npx tsx test_full_cycle.ts

1. Generating Merkle Tree (local)...
   Merkle root: 0x0b015d3771810ae636b73f3e9d77e062cc92ffb881666aaf68fffffce596bc81
   -> Time of the Merkle Tree: 98.133ms

2. Generating ZK Proof (Client side)...
   Proof cryptographic computed successfully!
   -> Time of the Proof (Prover): 7.082s

3. Sending the Proof to the Auditor (Verification side)...

--- FINAL RESULT OF THE AUDIT ---
✅ EXCELLENT: Proof 100% Valid in the Groth16 Circuit!
-> Verification Time (Verifier): 22.177ms

------------------------------------
Total cycle time: 7.228s

```
## **Note**: Proving is executed entirely client-side using WebAssembly, ensuring strict user privacy with zero data tracking. Verification is sub-millisecond level, optimized for high-throughput Web3 applications.
---

## 🛠️ Roadmap & Technology Stack Note

* **Current Implementation:** Core cryptographic circuit written in Rust and compiled via `wasm-pack`. The benchmarking scripts are now fully migrated to TypeScript (TS) to enforce strict cryptographic type safety."
