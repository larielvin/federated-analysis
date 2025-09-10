require('dotenv').config();
const ethersLib = require('ethers');
const isV5 = !!ethersLib.providers;
const { abi } = require('../build/contracts/Notary.json');
const Provider = isV5 ? ethersLib.providers.JsonRpcProvider : ethersLib.JsonRpcProvider;
const parseUnits = isV5 ? ethersLib.utils.parseUnits : ethersLib.parseUnits;

const RPC = process.env.RPC_URL || 'https://rpc-amoy.polygon.technology';
const PRIV_KEY = process.env.PRIV_KEY; 
const CONTRACT_ADDR = '0x332BEF840Ab75c8B733A355AE7e07453bF485514';

(async () => {
  const provider = new Provider(RPC);
  const wallet = new ethersLib.Wallet(PRIV_KEY, provider);
  const notary = new ethersLib.Contract(CONTRACT_ADDR, abi, wallet);

  const bundleHash = (isV5 ? ethersLib.utils : ethersLib).keccak256(
    (isV5 ? ethersLib.utils : ethersLib).toUtf8Bytes('bundle-1')
  );
  const pcr0 = '0x' + 'ab'.repeat(48); // 48 bytes
  const ipfsCid = 'bafybeigdyrq7examplecidstringforipfs';

  const tx = await notary.anchor(bundleHash, pcr0, ipfsCid, {
    maxPriorityFeePerGas: parseUnits('60', 'gwei'),
    maxFeePerGas:        parseUnits('120', 'gwei'),
  });
  console.log('tx sent:', tx.hash);
  const rcpt = await tx.wait();
  console.log('mined in block', rcpt.blockNumber);

  // Read back last id
  const total = await notary.totalEntries();
  const entry = await notary.getEntry(total);
  console.log('Entry', total.toString(), entry);
})();
