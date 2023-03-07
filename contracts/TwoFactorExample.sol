pragma solidity ^0.8.9;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "./Authenticatable.sol";

contract TwoFactorExample is Authenticatable{
   
   address public owner;
   bytes32 public token;
   uint public freshness;
   
   constructor(AuthOracle _auth, Credentials memory credentials, uint _freshness) payable Authenticatable(_auth) checkCredentialsWithFactorAndFreshness(credentials, msg.sender, "email", 
   _freshness){
       owner = msg.sender;
       token = credentials.token;
       freshness = _freshness;
   }

   function withdraw(Credentials memory credentials, uint256 amount) public checkCredentialsWithFactorAndFreshness(credentials, msg.sender, "email", freshness) {
       require(owner == msg.sender);
       require(token == credentials.token);
       payable(msg.sender).transfer(amount);
   }
}