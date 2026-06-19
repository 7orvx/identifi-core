# IdentiFI Core (ZK-Engine)

The core cryptographic engine of the **IdentiFI Protocol**, a stateless, privacy-preserving authority layer built for Web3 and decentralized applications. This module features a high-performance ZK-SNARK circuit using Groth16, compiled natively from Rust to WebAssembly (WASM) to run blindingly fast client-side proving and local verification.

## 🚀 Quick Start / Running the Tests

To audit and validate the zero-knowledge proof generation and Merkle tree logic locally, you can run the benchmarking scripts using Node.js.

### Prerequisites
Make sure you have [Node.js](https://nodejs.org/) installed on your machine.

### Execution Commands
Run the following commands in your terminal from the root of the `identifi-core` directory:

1. **Test the Full Cryptographic Cycle (Prover & Verifier):**
```bash
   npm run test:full

```

2. **Test the Local Merkle Tree Proof Generation:**

```bash
   npm run test:merkle

```

---

## 🛠️ Roadmap & Technology Stack Note

* **Current Implementation:** Core cryptographic circuit written in Rust and compiled via `wasm-pack`. The current local benchmarking scripts are written in JavaScript/ESM (`.mjs`).
* **Next Steps (TypeScript Migration):** As you will notice from the pre-compiled `.d.ts` files already available in the `/pkg` directory, **the entire IdentiFI SDK and ecosystem interfaces are actively being migrated to TypeScript (TS)**. This migration will enforce strict cryptographic type safety, seamless dApp integration, and clean developer workflows for upcoming features.