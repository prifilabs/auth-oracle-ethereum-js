// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./AuthOracle.sol";

struct Credentials {
    bytes sender;
    bytes validator;
    bytes32 token;
    bytes32 factor;
    uint timestamp;
}

abstract contract Authenticatable {
    
    AuthOracle public auth;
 
    error InvalidCredentials(string reason);
    
    constructor(AuthOracle _auth) {
        auth = _auth;
    }
    
    modifier checkCredentials(Credentials memory credentials, address owner){
        _checkCredentials(credentials, owner);
        _;
    }
    
    modifier checkCredentialsWithFactor(Credentials memory credentials, address owner, bytes32 factor) {
        _checkCredentials(credentials, owner);
        _checkFactor(credentials, factor);
        _;
    }
    
    modifier checkCredentialsWithFreshness(Credentials memory credentials, address owner, uint freshness) {
        _checkCredentials(credentials, owner);
        _checkFreshness(credentials, freshness);
        _;
    }
    
    
    modifier checkCredentialsWithFactorAndFreshness(Credentials memory credentials, address owner, bytes32 factor, uint freshness){
        _checkCredentials(credentials, owner);
        _checkFactor(credentials, factor);
        _checkFreshness(credentials, freshness);
        _;
    }
    
    function _checkFactor(Credentials memory credentials, bytes32 factor) private pure {
        if (credentials.factor != factor) {
            revert InvalidCredentials("The factor does not match");
        }
    }
    
    function _checkFreshness(Credentials memory credentials, uint freshness) private view {
        if ((credentials.timestamp + freshness) < block.timestamp){
            revert InvalidCredentials("The credentials have expired");
        }
    }
    
    using ECDSA for bytes32;
    
    function _checkCredentials(Credentials memory credentials, address owner) private view {
        bytes32 signerHash = keccak256(abi.encode(credentials.factor, credentials.timestamp));
        address signer = signerHash.toEthSignedMessageHash().recover(credentials.sender);
        if (credentials.timestamp > block.timestamp){
            revert InvalidCredentials("The timestamp is post-dated");
        }
        if (signer != owner){
            revert InvalidCredentials("The owner signature does not match");
        }
        bytes32 validatorHash = keccak256(abi.encode(credentials.sender, credentials.token));
        address validator = validatorHash.toEthSignedMessageHash().recover(credentials.validator);
        if (!auth.isValid(validator)){
            revert InvalidCredentials("The validator signature is not trusted");
        }
    }
    
    
}
