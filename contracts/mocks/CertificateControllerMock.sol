pragma solidity ^0.5.0;

import "openzeppelin-solidity/contracts/cryptography/ECDSA.sol";

contract CertificateControllerMock {

  // If set to 'true', the certificate control is activated
  bool _certificateControllerActivated;

  // Address used by off-chain controller service to sign certificate
  mapping(address => bool) internal _certificateSigners;

  // A nonce used to ensure a certificate can be used only once
  mapping(address => uint256) internal _checkCount;

  event Checked(address sender);

  constructor(address _certificateSigner, bool activated) public {
    _setCertificateSigner(_certificateSigner, true);
    _certificateControllerActivated = activated;
  }

  /**
   * @dev Modifier to protect methods with certificate control
   */
  modifier isValidCertificate(bytes memory data) {

    if(_certificateControllerActivated) {
      require(_certificateSigners[msg.sender] || _checkCertificate(data, 0, 0x00000000), "A3"); // Transfer Blocked - Sender lockup period not ended

      _checkCount[msg.sender] += 1; // Increment sender check count

      emit Checked(msg.sender);
    }

    _;
  }

  /**
   * @dev Get number of transations already sent to this contract by the sender
   * @param sender Address whom to check the counter of.
   * @return uint256 Number of transaction already sent to this contract.
   */
  function checkCount(address sender) external view returns (uint256) {
    return _checkCount[sender];
  }

  /**
   * @dev Get certificate signer authorization for an operator.
   * @param operator Address whom to check the certificate signer authorization for.
   * @return bool 'true' if operator is authorized as certificate signer, 'false' if not.
   */
  function certificateSigners(address operator) external view returns (bool) {
    return _certificateSigners[operator];
  }

  /**
   * @dev Set signer authorization for operator.
   * @param operator Address to add/remove as a certificate signer.
   * @param authorized 'true' if operator shall be accepted as certificate signer, 'false' if not.
   */
  function _setCertificateSigner(address operator, bool authorized) internal {
    require(operator != address(0)); // Action Blocked - Not a valid address
    _certificateSigners[operator] = authorized;
  }


  /**
   * @dev Get activation status of certificate controller.
   */
  function certificateControllerActivated() external view returns (bool) {
    return _certificateControllerActivated;
  }

  /**
   * @dev Activate/disactivate certificate controller.
   * @param activated 'true', if the certificate control shall be activated, 'false' if not.
   */
  function _setCertificateControllerActivated(bool activated) internal {
    _certificateControllerActivated = activated;
  }

  struct CertificatePayload {
    bytes4 methodId;
    bytes32 parametersHash;
    uint256 validUntil;
    uint256 nonce;
    address signer;
  }

  using ECDSA for bytes32;

  function _getCertificatePayload(bytes memory certificate) internal pure returns(CertificatePayload memory) {
      (bytes memory encodedData, bytes memory signature) = abi.decode(certificate, (bytes, bytes));

      bytes32 encodedDataHash = ECDSA.toEthSignedMessageHash(keccak256(encodedData));
      address signer = ECDSA.recover(encodedDataHash, signature);

      (
        bytes4 methodId,
        bytes32 parametersHash,
        uint256 validUntil,
        uint256 nonce
      ) = abi.decode(encodedData, (bytes4, bytes32, uint256, uint256));

      return CertificatePayload(methodId, parametersHash, validUntil, nonce, signer);
  }

  /**
   * @dev Checks if a certificate is correct
   * @param data Certificate to control
   */
   function _checkCertificate(bytes memory data, uint256 /*value*/, bytes4 /*functionSig*/) internal view returns(bool) { // Comments to avoid compilation warnings for unused variables.
      CertificatePayload memory certificatePayload = _getCertificatePayload(data);
      require(_certificateSigners[certificatePayload.signer], "Invalid certifier signature");
      return true;
      // if(data.length > 0 && (data[0] == hex"10" || data[0] == hex"11" || data[0] == hex"22" || data[0] == hex"33")) {
      //   return true;
      // } else {
      //   return false;
      // }
   }
}
