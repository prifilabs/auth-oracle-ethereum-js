import { expect } from "chai";
import { ethers } from "ethers";

import * as pkg from "../src/index";

describe("Auth Oracle JS", function () {
      
    const E = pkg.ValidationError;      
    const handle = "alice@example.com";
    const factor = "email";
    const freshness = 10 // minutes
    
    const validateHandle = function(email){
        return String(email)
                .toLowerCase()
                .match(
                    /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
                );
    }
          
    describe("Basics", function () {
        it("Should sign data and verify its signature", async function () {
            const alice = ethers.Wallet.createRandom();
            let types = ['address', 'bytes32', 'uint', 'string'];
            let values = [alice.address, ethers.utils.formatBytes32String("email"), 0, "alice@example.com"];
            let signature = await pkg.signData(alice, types, values);
            let signer = await pkg.getSigner(types, values, signature);
            expect(signer).to.equal(alice.address);
        });
        
        it("should create secrets", async function () {
           const config = await pkg.createSecrets();
           expect(config).to.have.property('mnemonic');
           expect(config).to.have.property('key');
        });
    });

    describe("Request", function () {
        
        let alice, config, request;
        
        beforeEach(async function() {
            alice = ethers.Wallet.createRandom();
            request = await pkg.createRequest(alice, factor, handle);
            config = { factors: [factor] , validateHandle, freshness};
        });
        
        it("should create a request", async function () {
           expect(request).to.have.property('factor', ethers.utils.formatBytes32String(factor));
           expect(request).to.have.property('timestamp').which.is.above(0);
           expect(request).to.have.property('sender');
           expect(request).to.have.property('handle', handle);
           expect(request).to.have.property('verifier');
        });
        
        it("should encode/decode a request", async function () {
           const encodedRequest = pkg.encodeRequest(request);
           const checkRequest = pkg.decodeRequest(encodedRequest);
           expect(checkRequest).to.have.property('factor', request.factor);
           expect(checkRequest).to.have.property('timestamp', request.timestamp);
           expect(checkRequest).to.have.property('sender', request.sender);
           expect(checkRequest).to.have.property('handle', request.handle);
           expect(checkRequest).to.have.property('verifier', request.verifier);
        });
        
        it("Should validate a createRequest", async function () {
            let res = await pkg.checkRequest(config, request);
            expect(res).to.have.same.members([]);
        });

        it("Should reject an empty request", async function () {
            let res = await pkg.checkRequest(config, {});
            expect(res).to.have.same.members([E.FACTOR_FORMAT_ERROR, E.TIMESTAMP_FORMAT_ERROR, E.HANDLE_FORMAT_ERROR, E.INVALID_SENDER_SIGNATURE_ERROR, E.INVALID_VERIFIER_SIGNATURE_ERROR]);
        });
        
        it("Should reject an invalid request", async function () {
            let config = {
                factors: [],
                validateHandle: () => false,
                freshness: freshness,
            }
            let res = await pkg.checkRequest(config, request);
            expect(res).to.have.same.members([E.FACTOR_FORMAT_ERROR, E.HANDLE_FORMAT_ERROR]);
        });
        
        it("Should reject an invalid signature ", async function () {
            let mallory = ethers.Wallet.createRandom();
            let badCredentials = await pkg.createRequest(mallory, factor, handle);
            request.verifier = badCredentials.verifier;
            let res = await pkg.checkRequest(config, request);
            expect(res).to.have.same.members([E.SIGNATURE_MISMATCH_ERROR]);
        });
        
        it("Should reject expired request", async function () {
            let old = Math.floor(new Date().getTime() / 1000) - (freshness * 2);
            let badRequest = await pkg.createRequest(alice, factor, handle, old);
            let res = await pkg.checkRequest(config, badRequest);
            expect(res).to.have.same.members([E.OUTDATED_TIMESTAMP_ERROR]);
        });
        
        it("Should reject a timestamp in the future", async function () {
            let old = Math.floor(new Date().getTime() / 1000) + (freshness * 2);
            let badRequest = await pkg.createRequest(alice, factor, handle, old);
            let res = await pkg.checkRequest(config, badRequest);
            expect(res).to.have.same.members([E.POSTDATED_TIMESTAMP_ERROR]);
        });

    });
    
    describe("Credentials", function () {
        
        let alice, backendConfig, config, credentials;
        
        beforeEach(async function() {
            alice = ethers.Wallet.createRandom();
            const request = await pkg.createRequest(alice, factor, handle);
            backendConfig = await pkg.createSecrets();
            credentials = await pkg.createCredentials(backendConfig, request);
            const validator = ethers.Wallet.fromMnemonic(backendConfig.mnemonic);
            const isValid = (address) => (validator.address === address);
            config = {factors: [factor], isValid, freshness};
        });
        
        it("should create credentials", async function () {
            expect(credentials).to.have.property('factor', ethers.utils.formatBytes32String(factor));
            expect(credentials).to.have.property('timestamp').which.is.above(0);
            expect(credentials).to.have.property('sender');
            expect(credentials).to.have.property('token').which.not.equals(ethers.constants.HashZero);
            expect(credentials).to.have.property('validator');
         });
         
         it("should encode/decode credentials", async function () {
            const encodedCredentials = pkg.encodeCredentials(credentials);
            const checkCredentials = pkg.decodeCredentials(encodedCredentials);
            expect(checkCredentials).to.have.property('factor', credentials.factor);
            expect(checkCredentials).to.have.property('timestamp', credentials.timestamp);
            expect(checkCredentials).to.have.property('sender', credentials.sender);
            expect(checkCredentials).to.have.property('token', credentials.token);
            expect(checkCredentials).to.have.property('validator', credentials.validator);
         });
         
         it("Should validate a createCredentials", async function () {
             let res = await pkg.checkCredentials(config, credentials);
             expect(res).to.have.same.members([]);
         });
         
         it("Should reject empty credentials", async function () {
             let res = await pkg.checkCredentials(config, {});
             expect(res).to.have.same.members([E.FACTOR_FORMAT_ERROR, E.TOKEN_FORMAT_ERROR,  E.TIMESTAMP_FORMAT_ERROR, E.INVALID_SENDER_SIGNATURE_ERROR, E.INVALID_VALIDATOR_SIGNATURE_ERROR]);
         });

         it("Should reject invalid credentials", async function () {
             let config = {
                 factors: [],
                 isValid: () => false,
                 freshness: freshness,
             }
             let res = await pkg.checkCredentials(config, credentials);
             expect(res).to.have.same.members([E.FACTOR_FORMAT_ERROR, E.UNTRUSTED_VALIDATOR_ERROR]);
         });
         
         it("Should reject expired request", async function () {
             let old = Math.floor(new Date().getTime() / 1000) - (freshness * 2);
             let badRequest = await pkg.createRequest(alice, factor, handle, old);
             let badCredentials = await pkg.createCredentials(backendConfig, badRequest);
             let res = await pkg.checkCredentials(config, badCredentials);
             expect(res).to.have.same.members([E.OUTDATED_TIMESTAMP_ERROR]);
         });
        
         it("Should reject a timestamp in the future", async function () {
             let old = Math.floor(new Date().getTime() / 1000) + (freshness * 2);
             let badRequest = await pkg.createRequest(alice, factor, handle, old);
             let badCredentials = await pkg.createCredentials(backendConfig, badRequest);
             let res = await pkg.checkCredentials(config, badCredentials);
             expect(res).to.have.same.members([E.POSTDATED_TIMESTAMP_ERROR]);
         });
         
    });

});