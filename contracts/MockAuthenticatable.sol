pragma solidity ^0.8.9;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "./Authenticatable.sol";

contract MockAuthenticatable is Authenticatable{

   constructor(AuthOracle _auth) Authenticatable(_auth){
       
   }

   function checkCredentialsTest(Credentials memory credentials) public view checkCredentials(credentials, msg.sender) returns(bool){
       return true;
   }
   
   function checkCredentialsWithFactorTest(Credentials memory credentials, bytes32 factor) public view checkCredentialsWithFactor(credentials, msg.sender, factor) returns(bool){
       return true;
   }
   
   function checkCredentialsWithFreshnessTest(Credentials memory credentials, uint freshness) public view checkCredentialsWithFreshness(credentials, msg.sender, freshness) returns(bool){
       return true;
   }
   
   function checkCredentialsWithFactorAndFreshnessTest(Credentials memory credentials, bytes32 factor, uint freshness) public view checkCredentialsWithFactorAndFreshness(credentials, msg.sender, factor, freshness) returns(bool){
       return true;
   }
}