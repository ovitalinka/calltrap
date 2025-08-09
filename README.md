# calltrap — hunt hidden calls inside calldata blobs

**calltrap** is a zero-RPC CLI that scans Ethereum calldata and **discovers nested
calls** hiding inside dynamic `bytes`/`bytes[]` arguments (e.g., `multicall(bytes[])`,
`permitAndCall`, proxy `initialize(data)`, arbitrary `execute(...,bytes)` hooks).

No ABI. No internet. It uses ABI layout heuristics to:
- find dynamic regions via offsets,
- recognize array-of-bytes patterns (`bytes[]`),
- pull out the first 4 bytes as a selector,
- label well-known risky methods (`approve`, `setApprovalForAll`, `permit`, `upgradeTo`, `initialize`),
- estimate a frame length (head+tail) and assign a **LOW/MEDIUM/HIGH** risk tag.

## Why this matters

Attackers and rushed upgrades often **hide approvals** or risky admin calls inside
nested payloads. Reviewers see only “multicall” or “initialize(data)”. **calltrap**
peels the onion so you can see the inner calls before signing.

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
