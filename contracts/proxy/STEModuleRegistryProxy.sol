pragma solidity ^0.5.0;

import "../storage/EternalStorage.sol";
import "./OwnedUpgradeabilityProxy.sol";

/**
 * @title STEModuleRegistryProxy
 * @dev This proxy has the eternal storage, and allows you to delegate where the STEModuleRegistry implementation is
 * Upgrade the STEModuleRegistry
 */

contract STEModuleRegistryProxy is EternalStorage, OwnedUpgradeabilityProxy {

}
