"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createSecrets = exports.decodeCredentials = exports.createCredentials = exports.createRequest = exports.checkCredentials = exports.checkRequest = exports.validationErrors = exports.getSigner = exports.signData = void 0;
var ethers_1 = require("ethers");
function signData(signer, types, values) {
    return __awaiter(this, void 0, void 0, function () {
        var message;
        return __generator(this, function (_a) {
            message = ethers_1.utils.arrayify(ethers_1.utils.keccak256(ethers_1.utils.defaultAbiCoder.encode(types, values)));
            return [2 /*return*/, signer.signMessage(message)];
        });
    });
}
exports.signData = signData;
function getSigner(types, values, signature) {
    var message = ethers_1.utils.arrayify(ethers_1.utils.keccak256(ethers_1.utils.defaultAbiCoder.encode(types, values)));
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
        var f = ethers_1.utils.parseBytes32String(factor);
        return (factors.indexOf(f) > -1);
    }
    catch (e) {
        return false;
    }
}
function checkRequest(config, request) {
    return __awaiter(this, void 0, void 0, function () {
        var validateHandle, factors, sender, factor, handle, signature, res, senderCheck;
        return __generator(this, function (_a) {
            validateHandle = config.validateHandle, factors = config.factors;
            sender = request.sender, factor = request.factor, handle = request.handle, signature = request.signature;
            res = [];
            if (!checkAddress(sender)) {
                res.push('SENDER_FORMAT_ERROR');
            }
            if (!checkFactor(factors, factor)) {
                res.push('FACTOR_FORMAT_ERROR');
            }
            if (!validateHandle(handle)) {
                res.push('HANDLE_FORMAT_ERROR');
            }
            try {
                senderCheck = getSigner(['address', 'bytes32', 'string'], [sender, factor, handle], signature);
                if (senderCheck !== sender) {
                    res.push('INVALID_SIGNATURE');
                }
            }
            catch (e) {
                res.push('INVALID_SIGNATURE');
            }
            return [2 /*return*/, res];
        });
    });
}
exports.checkRequest = checkRequest;
function checkCredentials(config, credentials) {
    return __awaiter(this, void 0, void 0, function () {
        var factors, isValid, isRevoked, sender, signer, factor, token, timestamp, signature, res, t, signerCheck;
        return __generator(this, function (_a) {
            factors = config.factors, isValid = config.isValid, isRevoked = config.isRevoked;
            sender = credentials.sender, signer = credentials.signer, factor = credentials.factor, token = credentials.token, timestamp = credentials.timestamp, signature = credentials.signature;
            res = [];
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
            t = isRevoked(signer);
            if ((t !== 0) && (timestamp > t)) {
                res.push('REVOKED_SIGNER_ERROR');
            }
            try {
                signerCheck = getSigner(['address', 'address', 'bytes32', 'bytes32', 'uint'], [sender, signer, factor, token, timestamp], signature);
                if (signerCheck !== signer) {
                    res.push('INVALID_SIGNATURE');
                }
            }
            catch (e) {
                res.push('INVALID_SIGNATURE');
            }
            return [2 /*return*/, res];
        });
    });
}
exports.checkCredentials = checkCredentials;
function createRequest(signer, factor, handle) {
    return __awaiter(this, void 0, void 0, function () {
        var types, sender, values, signature;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    factor = ethers_1.utils.formatBytes32String(factor);
                    types = ['address', 'bytes32', 'string'];
                    return [4 /*yield*/, signer.getAddress()];
                case 1:
                    sender = _a.sent();
                    values = [sender, factor, handle];
                    return [4 /*yield*/, signData(signer, types, values)];
                case 2:
                    signature = _a.sent();
                    return [2 /*return*/, { sender: sender, factor: factor, handle: handle, signature: signature }];
            }
        });
    });
}
exports.createRequest = createRequest;
function createCredentials(config, request) {
    return __awaiter(this, void 0, void 0, function () {
        var sender, factor, handle, signature, key, token, timestamp, validator, signer, sig, credentials, encodedCredentials;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    sender = request.sender, factor = request.factor, handle = request.handle, signature = request.signature;
                    key = new Uint8Array(Buffer.from(config.key, 'base64'));
                    token = ethers_1.utils.computeHmac(ethers_1.utils.SupportedAlgorithm.sha256, key, ethers_1.utils.keccak256(ethers_1.utils.solidityPack(["bytes32", "string"], [factor, handle])));
                    timestamp = (config === null || config === void 0 ? void 0 : config.time) ? config.time : Math.floor(new Date().getTime() / 1000);
                    validator = ethers_1.Wallet.fromMnemonic(config.mnemonic);
                    return [4 /*yield*/, validator.getAddress()];
                case 1:
                    signer = _a.sent();
                    return [4 /*yield*/, signData(validator, ['address', 'address', 'bytes32', 'bytes32', 'uint'], [sender, signer, factor, token, timestamp])];
                case 2:
                    sig = _a.sent();
                    credentials = { sender: sender, signer: signer, factor: factor, token: token, timestamp: timestamp, signature: sig };
                    encodedCredentials = btoa(JSON.stringify(credentials));
                    return [2 /*return*/, encodedCredentials];
            }
        });
    });
}
exports.createCredentials = createCredentials;
function decodeCredentials(encodedCredentials) {
    return JSON.parse(atob(encodedCredentials));
}
exports.decodeCredentials = decodeCredentials;
;
function createSecrets() {
    return __awaiter(this, void 0, void 0, function () {
        var mnemonic, rd, key;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, ethers_1.Wallet.createRandom().mnemonic.phrase];
                case 1:
                    mnemonic = _a.sent();
                    rd = ethers_1.utils.randomBytes(32);
                    key = Buffer.from(rd).toString('base64');
                    return [2 /*return*/, { mnemonic: mnemonic, key: key }];
            }
        });
    });
}
exports.createSecrets = createSecrets;
