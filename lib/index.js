"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createSecrets = exports.decodeCredentials = exports.createCredentials = exports.createRequest = exports.checkCredentials = exports.checkRequest = exports.validationErrors = exports.getSigner = exports.signData = void 0;
const ethers_1 = require("ethers");
async function signData(signer, types, values) {
    let message = ethers_1.utils.arrayify(ethers_1.utils.keccak256(ethers_1.utils.defaultAbiCoder.encode(types, values)));
    return signer.signMessage(message);
}
exports.signData = signData;
function getSigner(types, values, signature) {
    let message = ethers_1.utils.arrayify(ethers_1.utils.keccak256(ethers_1.utils.defaultAbiCoder.encode(types, values)));
    return ethers_1.utils.verifyMessage(message, signature);
}
exports.getSigner = getSigner;
function isDefined(value) {
    // match both null and undefined
    return !(value == null);
}
function checkAddress(address) {
    return (isDefined(address) && ethers_1.utils.isAddress(address));
}
function checkToken(token) {
    return (isDefined(token));
}
function checkTimestamp(timestamp) {
    return (isDefined(timestamp) && !isNaN(timestamp) && ((new Date(timestamp * 1000)).getTime() > 0));
}
exports.validationErrors = {
    SENDER_FORMAT_ERROR: "The sender is not a valid address",
    SIGNER_FORMAT_ERROR: "The signer is not a valid address",
    FACTOR_FORMAT_ERROR: "The factor is not a valid factor",
    TOKEN_FORMAT_ERROR: "The factor is not a valid bytes32",
    TIMESTAMP_FORMAT_ERROR: "The timestamp is not a valid date",
    HANDLE_FORMAT_ERROR: "The handle is not a valid string",
    INVALID_SIGNATURE: "The signature is invalid",
    UNTRUSTED_SIGNER_ERROR: "The signer is not trusted",
    REVOKED_SIGNER_ERROR: "The signer has been revoked",
};
function checkFactor(factors, factor) {
    try {
        let f = ethers_1.utils.parseBytes32String(factor);
        return (factors.indexOf(f) > -1);
    }
    catch (e) {
        return false;
    }
}
async function checkRequest(config, request) {
    let { validateHandle, factors } = config;
    let { sender, factor, handle, signature } = request;
    let res = [];
    if (!checkAddress(sender)) {
        res.push('SENDER_FORMAT_ERROR');
    }
    if (!checkFactor(factors, factor)) {
        res.push('FACTOR_FORMAT_ERROR');
    }
    if (!validateHandle(handle)) {
        res.push('HANDLE_FORMAT_ERROR');
    }
    let senderCheck;
    try {
        senderCheck = getSigner(['address', 'bytes32', 'string'], [sender, factor, handle], signature);
        if (senderCheck !== sender) {
            res.push('INVALID_SIGNATURE');
        }
    }
    catch (e) {
        res.push('INVALID_SIGNATURE');
    }
    return res;
}
exports.checkRequest = checkRequest;
async function checkCredentials(config, credentials) {
    let { factors, isValid, isRevoked } = config;
    let { sender, signer, factor, token, timestamp, signature } = credentials;
    let res = [];
    if (!checkAddress(sender)) {
        res.push('SENDER_FORMAT_ERROR');
    }
    if (!checkAddress(signer)) {
        res.push('SIGNER_FORMAT_ERROR');
    }
    if (!checkFactor(factors, factor)) {
        res.push('FACTOR_FORMAT_ERROR');
    }
    if (!checkToken(token)) {
        res.push('TOKEN_FORMAT_ERROR');
    }
    if (!checkTimestamp(timestamp)) {
        res.push('TIMESTAMP_FORMAT_ERROR');
    }
    if (!isValid(signer)) {
        res.push('UNTRUSTED_SIGNER_ERROR');
    }
    let t = isRevoked(signer);
    if ((t !== 0) && (timestamp > t)) {
        res.push('REVOKED_SIGNER_ERROR');
    }
    let signerCheck;
    try {
        signerCheck = getSigner(['address', 'address', 'bytes32', 'bytes32', 'uint'], [sender, signer, factor, token, timestamp], signature);
        if (signerCheck !== signer) {
            res.push('INVALID_SIGNATURE');
        }
    }
    catch (e) {
        res.push('INVALID_SIGNATURE');
    }
    return res;
}
exports.checkCredentials = checkCredentials;
async function createRequest(signer, factor, handle) {
    factor = ethers_1.utils.formatBytes32String(factor);
    let types = ['address', 'bytes32', 'string'];
    let sender = await signer.getAddress();
    let values = [sender, factor, handle];
    let signature = await signData(signer, types, values);
    return { sender, factor, handle, signature };
}
exports.createRequest = createRequest;
async function createCredentials(config, request) {
    let { sender, factor, handle, signature } = request;
    let key = new Uint8Array(Buffer.from(config.key, 'base64'));
    let token = ethers_1.utils.computeHmac(ethers_1.utils.SupportedAlgorithm.sha256, key, ethers_1.utils.keccak256(ethers_1.utils.solidityPack(["bytes32", "string"], [factor, handle])));
    let timestamp = (config?.time) ? config.time : Math.floor(new Date().getTime() / 1000);
    let validator = ethers_1.Wallet.fromMnemonic(config.mnemonic);
    let signer = await validator.getAddress();
    let sig = await signData(validator, ['address', 'address', 'bytes32', 'bytes32', 'uint'], [sender, signer, factor, token, timestamp]);
    let credentials = { sender, signer, factor, token, timestamp, signature: sig };
    let encodedCredentials = btoa(JSON.stringify(credentials));
    return encodedCredentials;
}
exports.createCredentials = createCredentials;
function decodeCredentials(encodedCredentials) {
    return JSON.parse(atob(encodedCredentials));
}
exports.decodeCredentials = decodeCredentials;
;
async function createSecrets() {
    const mnemonic = await ethers_1.Wallet.createRandom().mnemonic.phrase;
    const rd = ethers_1.utils.randomBytes(32);
    const key = Buffer.from(rd).toString('base64');
    return { mnemonic, key };
}
exports.createSecrets = createSecrets;
