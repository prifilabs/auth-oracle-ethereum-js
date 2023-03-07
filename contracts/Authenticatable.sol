// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./AuthOracle.sol";

struct Credentials {
    address sender;
    address signer;
    bytes32 token;
    bytes32 factor;
    uint timestamp;
    bytes signature;
}

abstract contract Authenticatable {
    
    AuthOracle public auth;
 
    error InvalidCredentials(string reason);
    
    constructor(AuthOracle _auth) {
        auth = _auth;
    }
    
    modifier checkCredentials(Credentials memory credentials, address sender){
        _checkCredentials(credentials, sender);
        _;
    }
    
    modifier checkCredentialsWithFactor(Credentials memory credentials, address sender, bytes32 factor) {
        _checkCredentials(credentials, sender);
        _checkFactor(credentials, factor);
        _;
    }
    
    modifier checkCredentialsWithFreshness(Credentials memory credentials, address sender, uint freshness) {
        _checkCredentials(credentials, sender);
        _checkFreshness(credentials, freshness);
        _;
    }
    
    
    modifier checkCredentialsWithFactorAndFreshness(Credentials memory credentials, address sender, bytes32 factor, uint freshness){
        _checkCredentials(credentials, sender);
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
    
    function _checkCredentials(Credentials memory credentials, address sender) private view {
        if (sender != credentials.sender){
            revert InvalidCredentials("The sender does not match");
        }
        if (!auth.isValid(credentials.signer)){
            revert InvalidCredentials("The signer is not trusted");
        }
        if ((auth.isRevoked(credentials.signer) != 0) && (auth.isRevoked(credentials.signer) < credentials.timestamp)){
            revert InvalidCredentials("The signer has been revoked");
        }
        bytes32 msgHash = keccak256(abi.encode(credentials.sender,  credentials.signer, credentials.factor,  credentials.token, credentials.timestamp));
        address signer = msgHash.toEthSignedMessageHash().recover(credentials.signature);
        if (credentials.signer != signer){
            revert InvalidCredentials("The signature is invalid");
        }
    }
    
    
}
