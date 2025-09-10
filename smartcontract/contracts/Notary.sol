// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Notary for Bundle Hash + PCR0 + IPFS CID + bundle name
contract Notary {
    struct Entry {
        address sender;
        bytes32 bundleHash;   // 32-byte digest
        bytes   pcr0;         // 48 bytes (SHA-384)
        string  ipfsCid;    
        string  bundleName;   // human-readable bundle label (n=bundlename)
        uint256 timestamp;
    }

    // Indexed for fast querying (max 3 indexed fields).
    event Anchored(
        address indexed sender,
        bytes32 indexed bundleHash,
        bytes32 indexed pcr0Hash, // keccak256(pcr0)
        bytes32 cidHash,          // keccak256(bytes(ipfsCid))
        bytes pcr0,
        string ipfsCid,
        string bundleName,
        uint256 id                // notary index
    );

    uint256 public totalEntries;
    mapping(uint256 => Entry) private entries;

    function anchor(
        bytes32 bundleHash,
        bytes calldata pcr0,
        string calldata ipfsCid,
        string calldata bundleName
    )
        external
        returns (uint256 id)
    {
        require(pcr0.length == 48, "PCR0 must be 48 bytes (SHA-384)");
        id = ++totalEntries;

        entries[id] = Entry({
            sender: msg.sender,
            bundleHash: bundleHash,
            pcr0: pcr0,
            ipfsCid: ipfsCid,
            bundleName: bundleName,
            timestamp: block.timestamp
        });

        emit Anchored(
            msg.sender,
            bundleHash,
            keccak256(pcr0),
            keccak256(bytes(ipfsCid)),
            pcr0,
            ipfsCid,
            bundleName,
            id
        );
    }

    function getEntry(uint256 id)
        external
        view
        returns (
            address sender,
            bytes32 bundleHash,
            bytes memory pcr0,
            string memory ipfsCid,
            string memory bundleName,
            uint256 timestamp
        )
    {
        Entry storage e = entries[id];
        require(e.timestamp != 0, "No such entry");
        return (e.sender, e.bundleHash, e.pcr0, e.ipfsCid, e.bundleName, e.timestamp);
    }

    /// @notice Return all entries. Suitable for off-chain calls (can be heavy if many entries).
    function getAllEntries() external view returns (Entry[] memory all) {
        uint256 n = totalEntries;
        all = new Entry[](n);
        for (uint256 i = 0; i < n; i++) {
            all[i] = entries[i + 1]; // entries are 1-indexed
        }
    }
}
