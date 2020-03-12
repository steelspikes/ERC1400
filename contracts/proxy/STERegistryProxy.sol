pragma solidity ^0.5.0;

import "../storage/EternalStorage.sol";
import "./OwnedUpgradeabilityProxy.sol";

/**
 * @title SecurityTokenRegistryProxy
 * @dev This proxy holds the storage of STERegistry proxy
 * Upgrade the STERegistry
 */

contract STERegistryProxy is EternalStorage, OwnedUpgradeabilityProxy {

}
