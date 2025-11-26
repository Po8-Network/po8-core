# Po8 Core Node

The reference implementation of the Po8 Network node software, written in Rust.

## Modules

*   **`po8-node`**: The main entry point, P2P networking, and RPC server.
*   **`po8-consensus`**: The TensorChain consensus engine implementing Proof-of-Useful-Work and Freivalds' Verification.
*   **`po8-miner`**: NPU-accelerated mining logic (C++ bridge to Apple MLX) and Proof Vector generation.
*   **`po8-vm`**: The execution layer wrapping `revm`, implementing the Quantum Abstraction Layer (QAL) for ML-DSA signature verification.
*   **`po8-crypto`**: High-level Rust bindings for `liboqs` (ML-KEM-768, ML-DSA-65).

## Building

### Prerequisites
*   Rust (latest stable)
*   C++ Compiler (Clang/GCC)
*   `liboqs` (installed via system package manager or built from source)
*   **macOS (Optional)**: Apple Silicon for hardware acceleration via MLX.

### Build Command
```bash
cargo build --release
```

### Running a Devnet Node
```bash
cargo run --bin po8-node
```
The node will start on `127.0.0.1:8833` (JSON-RPC) and `8834` (P2P).

