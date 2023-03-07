import { ethers } from "hardhat";

async function main() {

    const [deployer] = await ethers.getSigners();
    console.log("Deploying contracts with the account:", deployer.address);
    console.log("Account balance:", (await deployer.getBalance()).toString());
        
    const AuthOracle = await ethers.getContractFactory("AuthOracle");
    const auth = await AuthOracle.deploy();
    console.log("Auth Oracle address:", auth.address);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
