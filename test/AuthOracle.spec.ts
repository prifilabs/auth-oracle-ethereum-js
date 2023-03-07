import { time, loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { anyValue } from "@nomicfoundation/hardhat-chai-matchers/withArgs";
import { expect } from "chai";
import { ethers } from "hardhat";

describe("Auth Oracle", function () {
  
  async function deployAuthOracleFixture() {
      const [ owner, validator, mallory ] = await ethers.getSigners();
      const AuthOracle = await ethers.getContractFactory("AuthOracle");
      const contract = await AuthOracle.connect(owner).deploy();
      return { contract, owner, validator, mallory};
  }
  
  describe("Contract Deployment", function () {

    it("Should set the right owner", async function () {
      const { contract, owner } = await loadFixture(deployAuthOracleFixture);
      expect(await contract.owner()).to.equal(owner.address);
    });

  });

  describe("Add an Address", function () {

    it("Should allow owner to add an address", async function () {
      const { contract, owner, validator } = await loadFixture(deployAuthOracleFixture);
      await contract.connect(owner).addAddress(validator.address);
      expect(await contract.isValid(validator.address)).to.be.true;
    });

    it("Should not allow mallory to add an address", async function () {
        const { contract, mallory, validator } = await loadFixture(deployAuthOracleFixture);
        await expect(contract.connect(mallory).addAddress(validator.address)).to.be.reverted;
        expect(await contract.isValid(validator.address)).to.be.false;
    });

  });
  
  describe("Revoke an Address", function () {

    it("Should allow owner to revoke an address", async function () {
      const { contract, owner, validator } = await loadFixture(deployAuthOracleFixture);
      await contract.connect(owner).addAddress(validator.address);
      expect(await contract.isRevoked(validator.address)).to.equal(0);
      await contract.connect(owner).revokeAddress(validator.address);
      expect(await contract.isRevoked(validator.address)).to.be.above(0); 
    });

    it("Should not allow mallory to revoke an address", async function () {
        const { contract, owner, mallory, validator } = await loadFixture(deployAuthOracleFixture);
        await contract.connect(owner).addAddress(validator.address);
        expect(await contract.isRevoked(validator.address)).to.equal(0);
        await expect(contract.connect(mallory).revokeAddress(validator.address)).to.be.reverted;
        expect(await contract.isRevoked(validator.address)).to.equal(0);
    });

  });

});
