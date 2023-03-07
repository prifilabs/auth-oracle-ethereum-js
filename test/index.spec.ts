import { expect } from "chai";
import { ethers } from "ethers";

import { signData, getSigner, createSecrets, createRequest, createCredentials, decodeCredentials, checkRequest, checkCredentials, validationErrors} from "../src/index";

describe("Auth Oracle JS", function () {
      
    const handle = "alice@example.com";
    const factor = "email";
    const validateHandle = function(email){
        return String(email)
                .toLowerCase()
                .match(
                    /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
                );
    }
          
    describe("signData and getSigner", function () {
        it("Should sign data and verify its signature", async function () {
            const alice = ethers.Wallet.createRandom();
            let types = ['address', 'bytes32', 'uint', 'string'];
            let values = [alice.address, ethers.utils.formatBytes32String("email"), 0, "alice@example.com"];
            let signature = await signData(alice, types, values);
            let signer = await getSigner(types, values, signature);
            expect(signer).to.equal(alice.address);
        });
    });

    describe("createSecrets, createRequest createCredentials", function () {
        
        it("should create secrets", async function () {
           const config = await createSecrets();
           expect(config).to.have.property('mnemonic');
           expect(config).to.have.property('key');
        });
        
        it("should create a request", async function () {
           const alice = ethers.Wallet.createRandom();
           const request = await createRequest(alice, factor, handle);
           expect(request).to.have.property('sender', alice.address);
           expect(request).to.have.property('factor', ethers.utils.formatBytes32String(factor));
           expect(request).to.have.property('handle', handle);
           expect(request).to.have.property('signature');
        });
        
        it("should create credentials", async function () {
            const alice = ethers.Wallet.createRandom();
            const config = await createSecrets();
            const request = await createRequest(alice, factor, handle);
            let encodedCredentials = await createCredentials(config, request);
            let credentials = decodeCredentials(encodedCredentials);
            let validator = ethers.Wallet.fromMnemonic(config.mnemonic);
            let signer = await validator.getAddress();
            expect(credentials).to.have.property('signer', signer);
            expect(credentials).to.have.property('sender', request.sender);
            expect(credentials).to.have.property('factor', request.factor);
            expect(credentials).to.have.property('token').which.not.equals(ethers.constants.HashZero);
            expect(credentials).to.have.property('timestamp').which.is.above(0);
            expect(credentials).to.have.property('signature');
         });
    });
    
    describe("validateRequest", function () {
        
        let alice, config, request; 
        
        beforeEach(async function() {
            alice = ethers.Wallet.createRandom();
            request = await createRequest(alice, factor, handle);
            config = { factors: [factor] , validateHandle};
        });
        
        it("Should validate a createRequest", async function () {
            let res = await checkRequest(config, request);
            expect(res).to.have.same.members([]);
        });
        
        it("Should reject an empty request", async function () {
            let res = await checkRequest(config, {});
            expect(res).to.have.same.members(['SENDER_FORMAT_ERROR','FACTOR_FORMAT_ERROR','HANDLE_FORMAT_ERROR','INVALID_SIGNATURE']);
        });
        
        it("Should reject an invalid request", async function () {
            let config = {
                factors: [],
                validateHandle: () => false,
            }
            request.sender = request.sender.substring(0,5);
            let res = await checkRequest(config, request);
            expect(res).to.have.same.members(['SENDER_FORMAT_ERROR','FACTOR_FORMAT_ERROR','HANDLE_FORMAT_ERROR','INVALID_SIGNATURE']);
        });
        
        it("Should reject an invalid signature ", async function () {
            let mallory = ethers.Wallet.createRandom();
            let badCredentials = await createRequest(mallory, factor, handle);
            request.signature = badCredentials.signature;
            let res = await checkRequest(config, request);
            expect(res).to.have.same.members(['INVALID_SIGNATURE']);
        });
        
    });
    
    describe("validateRequest", function () {
        
        let alice, config, credentials;
        
        beforeEach(async function() {
            alice = ethers.Wallet.createRandom();
            const request = await createRequest(alice, factor, handle);
            const backendConfig = await createSecrets();
            const encodedCredentials = await createCredentials(backendConfig, request);
            credentials = decodeCredentials(encodedCredentials);
            const validator = ethers.Wallet.fromMnemonic(backendConfig.mnemonic);
            const isValid = (address) => (validator.address === address);
            const isRevoked = (address) => 0;
            config = {factors: [factor], isValid, isRevoked};    
        });
        
        it("Should validate a createCredentials", async function () {
            let res = await checkCredentials(config, credentials);
            expect(res).to.have.same.members([]);
        });
        
        it("Should validate a signer expired in the future", async function () {
            config.isRevoked = (address) => credentials.timestamp + 10;   
            let res = await checkCredentials(config, credentials);
            expect(res).to.have.same.members([]);
        });
        
        it("Should reject an expired signer", async function () {
            config.isRevoked = (address) => credentials.timestamp - 10;   
            let res = await checkCredentials(config, credentials);
            expect(res).to.have.same.members(['REVOKED_SIGNER_ERROR']);
        });
        
        it("Should reject an untrusted signer", async function () {
            config.isValid = (address) => false;
            let res = await checkCredentials(config, credentials);
            expect(res).to.have.same.members(['UNTRUSTED_SIGNER_ERROR']);
        });
        
        it("Should reject empty credentials", async function () {
            let res = await checkCredentials(config, {});
            expect(res).to.have.same.members(['SENDER_FORMAT_ERROR','SIGNER_FORMAT_ERROR','FACTOR_FORMAT_ERROR','TOKEN_FORMAT_ERROR','TIMESTAMP_FORMAT_ERROR','UNTRUSTED_SIGNER_ERROR','INVALID_SIGNATURE']);
        });
        
        it("Should reject invalid credentials", async function () {
            config.factors = [];
            credentials.sender = credentials.sender.substring(0,5);
            credentials.signer = credentials.sender.substring(0,5);
            credentials.timestamp = 'abcde';
            let res = await checkCredentials(config, credentials);
            expect(res).to.have.same.members(['SENDER_FORMAT_ERROR','SIGNER_FORMAT_ERROR','FACTOR_FORMAT_ERROR','TIMESTAMP_FORMAT_ERROR','UNTRUSTED_SIGNER_ERROR','INVALID_SIGNATURE']);
        });
        
        it("Should reject an invalid signature ", async function () {
            const request = await createRequest(alice, factor, handle);
            const backendConfig = await createSecrets();
            const encodedCredentials = await createCredentials(backendConfig, request);
            const badCredentials = decodeCredentials(encodedCredentials);
            credentials.signature = badCredentials.signature;
            let res = await checkCredentials(config, credentials);
            expect(res).to.have.same.members(['INVALID_SIGNATURE']);
        });
        
    });
         

});