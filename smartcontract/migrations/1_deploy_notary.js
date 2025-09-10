const Notary = artifacts.require("Notary");

module.exports = async function (deployer) {
  await deployer.deploy(Notary);
};
