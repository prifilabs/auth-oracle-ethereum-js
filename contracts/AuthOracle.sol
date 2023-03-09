// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

contract AuthOracle {

    address public owner; 
    mapping(address => bool) public isValid;
    
    constructor() public {
        owner = msg.sender;
    }
    
    function addAddress(address signer) public {
        require(msg.sender == owner);
        isValid[signer] = true;
    }
    
    function revokeAddress(address signer) public{
        require(msg.sender == owner);
        isValid[signer] = false;
    }
}
