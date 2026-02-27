# Unified UPI 2.0 (Hamilton)

Unified UPI 2.0 is a **next-generation tokenized payment system** designed for **high throughput, strong cryptographic security, and offline resilience**.  
Unlike traditional balance-based payment systems, it leverages a **UTXO (Unspent Transaction Output)** model — similar to Bitcoin — where digital value exists as **cryptographically signed tokens** instead of database ledger entries.

---

## Core Architecture

The system follows a **microservices-based architecture**, enabling scalability, modular deployment, and secure isolation of responsibilities.

### Components

| Component | Description |
|---|---|
| **Hamilton Core** | Central transaction processor that validates Ed25519 signatures and manages the global UTXO state |
| **Edge Wallet (CLI)** | Offline-capable wallet for key management, balance checks, and local transaction signing |
| **Merchant Client** | Payment acceptance service with QR generation and transaction callbacks |
| **Liquidity Bridge** | Gateway connecting tokenized money with Core Banking Systems (CBS) via mint/burn operations |
| **UTXO Store** | High-performance Redis state store ensuring atomic and double-spend-resistant updates |

---

## Key Features

### Tokenized Payments
Each currency unit exists as an independent **UTXO token** with cryptographic lineage and ownership proof.

### Offline Signing
The Edge Wallet allows transaction signing **without internet connectivity**. Signed transactions can be broadcast later for settlement.

### Cryptographic Security
- **Ed25519** → Digital signatures  
- **HMAC-SHA256** → Inter-service authentication  

### Deterministic Serialization
A custom **Canonical JSON encoder** ensures payload consistency so signatures remain valid across nodes and platforms.

### Bank-Grade Reliability
- Optimistic locking in Redis  
- Transactional integrity maintained via SQLite bridge records  

---

## Tech Stack

| Category | Technology |
|---|---|
| **Language** | Python 3.13+ |
| **Web Framework** | FastAPI (Async I/O) |
| **Database** | Redis (state & idempotency), SQLite (bridge records) |
| **Cryptography** | `cryptography`, `PyNaCl` |
| **CLI Framework** | Typer + Rich |

---

## Getting Started

### Prerequisites

- Python **3.13+**
- Redis Server running on `localhost:6379`

---

### Installation

```bash
pip install -r requirements.txt
```

## Running The Services

Start all microservices using the central orchestrator:

```bash
python main.py start-all
```

## Usage 

### Initialize the Edge Wallet

Generate a cryptographic identity secured with a password:

```bash
python main.py wallet init
```

## Check Balance

View tokenized holdings:

```bash
python main.py wallet balance --currency INR
```

## Security Implementation

### Idempotency

All critical operations (Mint, Burn, Process) use Redis-backed idempotency keys to prevent duplicate execution.

### Signature Verification

Hamilton Core reconstructs canonical JSON payloads from the UTXO store to verify token ownership before spending.

### Rate Limiting

1. IP-based throttling

2. Client-based request limiting

3. Protection against DoS attacks

### Fail-Closed Secrets

Merchant and Bridge services require environment variables for production secrets, preventing insecure default configurations.

## Testing

Run the full system test suite:

```bash
python test_system.py
```

### Test Coverage

1. Key generation validation

2. UTXO storage operations

3. End-to-end Alice → Bob transaction flow

4. Cryptographic verification logic