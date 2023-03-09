import { time, loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { anyValue } from "@nomicfoundation/hardhat-chai-matchers/withArgs";
import { expect } from "chai";
import { ethers } from "hardhat";

import { getSigner, signData, createRequest, createSecrets, createCredentials, decodeCredentials } from "../src/index";

describe("Authenticatable", function () {

    const factor = "email";
    const handle = "alice@example.com";
    const freshness = 10 // seconds

    async function credentialsRound(config, sender, factor, handle, timestamp?){
        const request = await createRequest(sender, factor, handle, timestamp);
        return createCredentials(config, request);
    }
  
    async function deployAuthOracleFixture() {
        const [ owner, alice, mallory ] = await ethers.getSigners();
        const config = await createSecrets();
        const validator = await ethers.Wallet.fromMnemonic(config.mnemonic);
        const provider = ethers.provider;
        const AuthOracle = await ethers.getContractFactory("AuthOracle");
        const auth = await AuthOracle.deploy();
        await auth.addAddress(validator.address);
        const MockAuthenticatable = await ethers.getContractFactory("MockAuthenticatable"); 
        const mock = await MockAuthenticatable.connect(alice).deploy(auth.address);
        return { mock, config, auth, owner, alice, mallory };
    }
    
    describe("Deployment", function () {
      it("Should set the auth", async function () {
          const { mock, auth } = await loadFixture(deployAuthOracleFixture);
          expect(await mock.auth()).to.equal(auth.address);
      });
    });

    describe("CheckCredentials", function () {

      it("Should succeed", async function () {
         const { mock, config, alice } = await loadFixture(deployAuthOracleFixture);
         const credentials = await credentialsRound(config, alice, factor, handle);
         expect(await mock.connect(alice).checkCredentialsTest(credentials)).to.be.true;
      });
      
      it("Should fail if the validator is not trusted", async function () {
         const { mock, config, alice } = await loadFixture(deployAuthOracleFixture);
         const { mnemonic, key } = await createSecrets();
         const provider = ethers.provider;
         const badConfig = {mnemonic, key, provider};
         const credentials = await credentialsRound(badConfig, alice, factor, handle);
         await expect(mock.connect(alice).checkCredentialsTest(credentials)).to.be.revertedWithCustomError(mock, "InvalidCredentials");
      });

      it("Should fail if the sender does not match", async function () {
         const { mock, config, alice, mallory } = await loadFixture(deployAuthOracleFixture);
         const credentials = await credentialsRound(config, alice, factor, handle);
         await expect(mock.connect(mallory).checkCredentialsTest(credentials)).to.be.revertedWithCustomError(mock, "InvalidCredentials");
      });
      
      it("Should fail if the timestamp is post-dated", async function () {
         const { mock, config, alice } = await loadFixture(deployAuthOracleFixture);
         let old = Math.floor(new Date().getTime() / 1000) + (freshness * 2);
         const credentials = await credentialsRound(config, alice, factor, handle, old);
         await expect(mock.connect(alice).checkCredentialsTest(credentials)).to.be.revertedWithCustomError(mock, "InvalidCredentials");
      });
    });
    
    describe("checkCredentialsWithFactor", function () {

      it("Should succeed if the factor does match", async function () {
         const { mock, config, alice } = await loadFixture(deployAuthOracleFixture);
         const credentials = await credentialsRound(config, alice, factor, handle);
         expect(await mock.connect(alice).checkCredentialsWithFactorTest(credentials, credentials.factor)).to.be.true;
      });
      
      it("Should fail if the factor does not match", async function () {
         const { mock, config, alice } = await loadFixture(deployAuthOracleFixture);
         const credentials = await credentialsRound(config, alice, factor, handle);
         await expect(mock.connect(alice).checkCredentialsWithFactorTest(credentials, ethers.utils.formatBytes32String("twitter"))).to.be.revertedWithCustomError(mock, "InvalidCredentials");
      });
      
    });
    
    describe("checkCredentialsWithFreshness", function () {

      it("Should succeed if the credentials are fresh", async function () {
         const { mock, config, alice } = await loadFixture(deployAuthOracleFixture);
         const credentials = await credentialsRound(config, alice, factor, handle);
         expect(await mock.connect(alice).checkCredentialsWithFreshnessTest(credentials, freshness)).to.be.true;
      });
      
      it("Should fail if the credentials are expired", async function () {
         const { mock, config, alice } = await loadFixture(deployAuthOracleFixture);
         const old = Math.floor(new Date().getTime() / 1000) - (freshness * 2); 
         const credentials = await credentialsRound(config, alice, factor, handle, old);
         await expect(mock.connect(alice).checkCredentialsWithFreshnessTest(credentials, freshness)).to.be.revertedWithCustomError(mock, "InvalidCredentials");
      });
      
    });
    
    describe("checkCredentialsWithFactorAndFreshness", function () {

      it("Should succeed if the credentials are fresh and the factor match", async function () {
         const { mock, config, alice } = await loadFixture(deployAuthOracleFixture);
         const credentials = await credentialsRound(config, alice, factor, handle);
         expect(await mock.connect(alice).checkCredentialsWithFactorAndFreshnessTest(credentials, credentials.factor, freshness)).to.be.true;
      });
      
      it("Should fail if the factor does not match", async function () {
         const { mock, config, alice } = await loadFixture(deployAuthOracleFixture);
         const credentials = await credentialsRound(config, alice, factor, handle);
         await expect(mock.connect(alice).checkCredentialsWithFactorAndFreshnessTest(credentials, ethers.utils.formatBytes32String("twitter"), freshness)).to.be.revertedWithCustomError(mock, "InvalidCredentials");
      });
      
      
      it("Should fail if the credentials are expired", async function () {
         const { mock, config, alice } = await loadFixture(deployAuthOracleFixture);
         const old = Math.floor(new Date().getTime() / 1000) - (freshness * 2); 
         const credentials = await credentialsRound(config, alice, factor, handle, old);
         await expect(mock.connect(alice).checkCredentialsWithFactorAndFreshnessTest(credentials, credentials.factor, freshness)).to.be.revertedWithCustomError(mock, "InvalidCredentials");
      });
      
    });
});