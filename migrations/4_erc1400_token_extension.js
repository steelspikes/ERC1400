const ERC1400ERC20 = artifacts.require('./ERC1400ERC20.sol');
const Extension = artifacts.require('./ERC1400TokensValidator.sol');

const CERTIFICATE_SIGNER = '0xfe28B202Dba5b6Dd9d7EC7158D584436676736E8';
const controller = '0xBc86e77dbFff634b4554Da461A92F1C97678C87f';

const partition1 = '0x5265736572766564000000000000000000000000000000000000000000000000'; // Reserved in hex
const partition2 = '0x4973737565640000000000000000000000000000000000000000000000000000'; // Issued in hex
const partition3 = '0x4c6f636b65640000000000000000000000000000000000000000000000000000'; // Locked in hex
const partitions = [partition1, partition2, partition3];

const ERC1400_TOKENS_VALIDATOR = 'ERC1400TokensValidator';

module.exports = async function (deployer, network, accounts) {
  const tokenInstance = await ERC1400ERC20.deployed();
  console.log('\n   > Add token extension for token deployed at address', tokenInstance.address);
  await deployer.deploy(Extension, true, false);
  console.log('\n   > Token extension deployment: Success -->', Extension.address);
  await tokenInstance.setHookContract(Extension.address, ERC1400_TOKENS_VALIDATOR);
  console.log('\n   > Token connection to extension: Success');
};
