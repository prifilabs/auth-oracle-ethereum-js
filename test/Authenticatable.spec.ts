import { time, loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { anyValue } from "@nomicfoundation/hardhat-chai-matchers/withArgs";
import { expect } from "chai";
import { ethers } from "hardhat";

import { getSigner, signData, createRequest, createSecrets, createCredentials, decodeCredentials } from "../src/index";

describe("Authenticatable", function () {

    const factor = "email";
    const handle = "alice@example.com";
    const freshness = 30; //seconds

    async function credentialsRound(config, sender, factor, handle){
        const request = await createRequest(sender, factor, handle);
        let encodedCredentials = await createCredentials(config, request);
        return decodeCredentials(encodedCredentials);
    }
  
    async function deployAuthOracleFixture() {
        const [ owner, alice, mallory ] = await ethers.getSigners();
        const backendConfig = await createSecrets();
        const validator = await ethers.Wallet.fromMnemonic(backendConfig.mnemonic);
        const provider = ethers.provider;
        const AuthOracle = await ethers.getContractFactory("AuthOracle");
        const auth = await AuthOracle.deploy();
        await auth.addAddress(validator.address);
        const MockAuthenticatable = await ethers.getContractFactory("MockAuthenticatable"); 
        const mock = await MockAuthenticatable.connect(alice).deploy(auth.address);
        return { mock, backendConfig, auth, owner, alice, mallory };
    }
    
    describe("Deployment", function () {
      it("Should set the auth", async function () {
          const { mock, auth } = await loadFixture(deployAuthOracleFixture);
          expect(await mock.auth()).to.equal(auth.address);
      });
    });

    describe("CheckCredentials", function () {

      it("Should succeed if the sender does match", async function () {
         const { mock, backendConfig, alice } = await loadFixture(deployAuthOracleFixture);
         const credentials = await credentialsRound(backendConfig, alice, factor, handle);
         expect(await mock.connect(alice).checkCredentialsTest(credentials)).to.be.true;
      });
      
      it("Should fail if the signer is not trusted", async function () {
         const { mock, backendConfig, alice } = await loadFixture(deployAuthOracleFixture);
         const { mnemonic, key } = await createSecrets();
         const provider = ethers.provider;
         const badConfig = {mnemonic, key, provider};
         const credentials = await credentialsRound(badConfig, alice, factor, handle);
         await expect(mock.connect(alice).checkCredentialsTest(credentials)).to.be.revertedWithCustomError(mock, "InvalidCredentials");
      });
      
      it("Should fail if the signer has expired", async function () {
         const { auth, mock, backendConfig, owner, alice, mallory } = await loadFixture(deployAuthOracleFixture);
         let validator = ethers.Wallet.fromMnemonic(backendConfig.mnemonic);
         let signer = await validator.getAddress();
         await auth.connect(owner).revokeAddress(signer);
         const time = Math.floor(new Date().getTime() / 1000) + 30; 
         const credentials = await credentialsRound({...backendConfig, time}, alice, factor, handle);
         await expect(mock.connect(alice).checkCredentialsTest(credentials)).to.be.revertedWithCustomError(mock, "InvalidCredentials");
      });
      
      it("Should fail if the signature does not match the signer", async function () {
         const { auth, mock, backendConfig, owner, alice, mallory } = await loadFixture(deployAuthOracleFixture);
         await auth.connect(owner).addAddress(mallory.address);
         const credentials = await credentialsRound(backendConfig, alice, factor, handle);
         credentials.signer = mallory.address;
         await expect(mock.connect(alice).checkCredentialsTest(credentials)).to.be.revertedWithCustomError(mock, "InvalidCredentials");
      });
      
      it("Should fail if the sender does not match", async function () {
         const { mock, backendConfig, alice, mallory } = await loadFixture(deployAuthOracleFixture);
         const credentials = await credentialsRound(backendConfig, alice, factor, handle);
         await expect(mock.connect(mallory).checkCredentialsTest(credentials)).to.be.revertedWithCustomError(mock, "InvalidCredentials");
      });
      
      it("Should fail if the signer is not trusted", async function () {
         const { mock, backendConfig, alice, mallory } = await loadFixture(deployAuthOracleFixture);
         const { mnemonic, key } = await createSecrets();
         const validator = await ethers.Wallet.fromMnemonic(mnemonic);
         const version = 0;
         const provider = ethers.provider;
         const config = {mnemonic, key, version, provider};
         const credentials = await credentialsRound(config, alice, factor, handle);
         await expect(mock.connect(mallory).checkCredentialsTest(credentials)).to.be.revertedWithCustomError(mock, "InvalidCredentials");
      });
    });
    
    describe("checkCredentialsWithFactor", function () {

      it("Should succeed if the factor does match", async function () {
         const { mock, backendConfig, alice } = await loadFixture(deployAuthOracleFixture);
         const credentials = await credentialsRound(backendConfig, alice, factor, handle);
         expect(await mock.connect(alice).checkCredentialsWithFactorTest(credentials, credentials.factor)).to.be.true;
      });
      
      it("Should fail if the factor does not match", async function () {
         const { mock, backendConfig, alice } = await loadFixture(deployAuthOracleFixture);
         const credentials = await credentialsRound(backendConfig, alice, factor, handle);
         await expect(mock.connect(alice).checkCredentialsWithFactorTest(credentials, ethers.utils.formatBytes32String("twitter"))).to.be.revertedWithCustomError(mock, "InvalidCredentials");
      });
      
      it("Should fail if the sender does not match", async function () {
         const { mock, backendConfig, alice, mallory } = await loadFixture(deployAuthOracleFixture);
         const credentials = await credentialsRound(backendConfig, alice, factor, handle);
         await expect(mock.connect(mallory).checkCredentialsWithFactorTest(credentials, credentials.factor)).to.be.revertedWithCustomError(mock, "InvalidCredentials");
      });
    });
    
    describe("checkCredentialsWithFreshness", function () {

      it("Should succeed if the credentials are fresh", async function () {
         const { mock, backendConfig, alice } = await loadFixture(deployAuthOracleFixture);
         const credentials = await credentialsRound(backendConfig, alice, factor, handle);
         expect(await mock.connect(alice).checkCredentialsWithFreshnessTest(credentials, freshness)).to.be.true;
      });
      
      it("Should fail if the credentials are expired", async function () {
         const { mock, backendConfig, alice } = await loadFixture(deployAuthOracleFixture);
         const time = Math.floor(new Date().getTime() / 1000) - (freshness * 2); 
         const credentials = await credentialsRound({...backendConfig, time}, alice, factor, handle);
         await expect(mock.connect(alice).checkCredentialsWithFreshnessTest(credentials, freshness)).to.be.revertedWithCustomError(mock, "InvalidCredentials");
      });
      
      it("Should fail if the sender does not match", async function () {
         const { mock, backendConfig, alice, mallory } = await loadFixture(deployAuthOracleFixture);
         const credentials = await credentialsRound(backendConfig, alice, factor, handle);
         await expect(mock.connect(mallory).checkCredentialsWithFreshnessTest(credentials, freshness)).to.be.revertedWithCustomError(mock, "InvalidCredentials");
      });
    });
    
    describe("checkCredentialsWithFactorAndFreshness", function () {

      it("Should succeed if the credentials are fresh", async function () {
         const { mock, backendConfig, alice } = await loadFixture(deployAuthOracleFixture);
         const credentials = await credentialsRound(backendConfig, alice, factor, handle);
         expect(await mock.connect(alice).checkCredentialsWithFactorAndFreshnessTest(credentials, credentials.factor, freshness)).to.be.true;
      });
      
      it("Should fail if the sender does not match", async function () {
         const { mock, backendConfig, alice, mallory } = await loadFixture(deployAuthOracleFixture);
         const credentials = await credentialsRound(backendConfig, alice, factor, handle);
         await expect(mock.connect(mallory).checkCredentialsWithFactorAndFreshnessTest(credentials, credentials.factor, freshness)).to.be.revertedWithCustomError(mock, "InvalidCredentials");
      });
      
      it("Should fail if the factor does not match", async function () {
         const { mock, backendConfig, alice } = await loadFixture(deployAuthOracleFixture);
         const credentials = await credentialsRound(backendConfig, alice, factor, handle);
         await expect(mock.connect(alice).checkCredentialsWithFactorAndFreshnessTest(credentials, ethers.utils.formatBytes32String("twitter"), freshness)).to.be.revertedWithCustomError(mock, "InvalidCredentials");
      });
      
      it("Should fail if the credentials are expired", async function () {
         const { mock, backendConfig, alice } = await loadFixture(deployAuthOracleFixture);
         const time = Math.floor(new Date().getTime() / 1000) - (freshness * 2); 
         const credentials = await credentialsRound({...backendConfig, time}, alice, factor, handle);
         await expect(mock.connect(alice).checkCredentialsWithFactorAndFreshnessTest(credentials, credentials.factor, freshness)).to.be.revertedWithCustomError(mock, "InvalidCredentials");
      });
      
    });
});