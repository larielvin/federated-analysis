require('dotenv').config();
const ethersLib = require('ethers');
const isV5 = !!ethersLib.providers;
const { abi } = require('../build/contracts/Notary.json');
const Provider = isV5 ? ethersLib.providers.JsonRpcProvider : ethersLib.JsonRpcProvider;

const RPC = process.env.RPC_URL || 'https://rpc-amoy.polygon.technology';
const CONTRACT_ADDR = '0x332BEF840Ab75c8B733A355AE7e07453bF485514';
const ID = parseInt(process.argv[2] || '1', 10);

(async () => {
  const provider = new Provider(RPC);
  const notary = new ethersLib.Contract(CONTRACT_ADDR, abi, provider);

  const e = await notary.getEntry(ID);
  console.log({
    sender: e.sender,
    bundleHash: e.bundleHash,
    pcr0: e.pcr0,
    ipfsCid: e.ipfsCid,
    timestamp: e.timestamp.toString(),
  });
})();
