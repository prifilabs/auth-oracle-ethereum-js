import { time, loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { anyValue } from "@nomicfoundation/hardhat-chai-matchers/withArgs";
import { expect } from "chai";
import { ethers } from "hardhat";

import { createSecrets, createRequest, createCredentials, decodeCredentials} from "../src/index";

describe("Two-Factor Example", function () {

    const factor = "email";
    const handle = "alice@example.com";

    async function credentialsRound(config, sender, factor, handle){
        const request = await createRequest(sender, factor, handle);
        let encodedCredentials = await createCredentials(config, request);
        return decodeCredentials(encodedCredentials);
    }
  
    async function deployAuthOracleFixture() {
        const [ owner, alice, mallory ] = await ethers.getSigners();
        const backendConfig  = await createSecrets();
        const validator = await ethers.Wallet.fromMnemonic(backendConfig.mnemonic);        
        const credentials = await credentialsRound(backendConfig, alice, factor, handle);
        
        const AuthOracle = await ethers.getContractFactory("AuthOracle");
        const auth = await AuthOracle.deploy();
        await auth.addAddress(validator.address);
        const TwoFactorExample = await ethers.getContractFactory("TwoFactorExample");
    
        const balance = ethers.utils.parseEther("100");
        const freshness = 30; // seconds
        const contractConfig = {balance, freshness};    
        const holder = await TwoFactorExample.connect(alice).deploy(auth.address, credentials, freshness, {value: balance});
        return { holder, auth, backendConfig, contractConfig, credentials, owner, alice, mallory };
    }
    
    describe("Deployment", function () {
      it("Should set the Auth Oracle", async function () {
          const { holder, auth } = await loadFixture(deployAuthOracleFixture);
          expect(await holder.auth()).to.equal(auth.address);
      });
      
      it("Should set the Alice as the owner", async function () {
          const { holder, credentials, alice } = await loadFixture(deployAuthOracleFixture);
          expect(await holder.owner()).to.equal(alice.address);
      });

      it("Should set the Alice's authentication token", async function () {
          const { holder, credentials } = await loadFixture(deployAuthOracleFixture);
          expect(await holder.token()).to.equal(credentials.token);
      });

      it("Should set the deadline", async function () {
          const { holder, contractConfig} = await loadFixture(deployAuthOracleFixture);
          expect(await holder.freshness()).to.equal(contractConfig.freshness);
      });

    });

    describe("Withdraw ETH", function () {

      let withdraw = ethers.utils.parseEther("60");
      let remaining = ethers.utils.parseEther("40");

      it("Should hold 100 ETH", async function () {
         const { holder, contractConfig } = await loadFixture(deployAuthOracleFixture);
         expect(await ethers.provider.getBalance(holder.address)).to.equal(contractConfig.balance);
      });

      it("Should allow Alice to withdraw", async function () {
          const { holder, backendConfig, alice } = await loadFixture(deployAuthOracleFixture);
          const credentials = await credentialsRound(backendConfig, alice, factor, handle);
          expect(await holder.connect(alice).withdraw(credentials, withdraw)).to.changeEtherBalance(alice, withdraw).and.to.changeEtherBalance(holder, -withdraw);
          expect(await ethers.provider.getBalance(holder.address)).to.equal(remaining);
      });

      it("Should not allow Alice to withdraw with different credentials", async function () {
          const { holder, backendConfig, contractConfig, alice } = await loadFixture(deployAuthOracleFixture);
          const credentials = await credentialsRound(backendConfig, alice, factor, "different.alice@example.com");
          await expect(holder.connect(alice).withdraw(credentials, withdraw)).to.be.reverted;
          expect(await ethers.provider.getBalance(holder.address)).to.equal(contractConfig.balance);
      });
      
      it("Should not allow Alice to withdraw with expired credentials", async function () {
          const { holder, backendConfig, contractConfig, alice } = await loadFixture(deployAuthOracleFixture);
          const time = Math.floor(new Date().getTime() / 1000) - 60; 
          const credentials = await credentialsRound({...backendConfig, time}, alice, factor, handle);
          await expect(holder.connect(alice).withdraw(credentials, withdraw)).to.be.reverted;
          expect(await ethers.provider.getBalance(holder.address)).to.equal(contractConfig.balance);
      });

      it("Should not allow Mallory to withdraw", async function () {
          const { holder, backendConfig, contractConfig, mallory } = await loadFixture(deployAuthOracleFixture);
          const credentials = await credentialsRound(backendConfig, mallory, factor, "mallory@example.com");
          await expect(holder.connect(mallory).withdraw(credentials, withdraw)).to.be.reverted;
          expect(await ethers.provider.getBalance(holder.address)).to.equal(contractConfig.balance);
      });

    });
});