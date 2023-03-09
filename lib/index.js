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
exports.createSecrets = exports.decodeCredentials = exports.encodeCredentials = exports.checkCredentials = exports.createCredentials = exports.checkRequest = exports.ValidationError = exports.decodeRequest = exports.encodeRequest = exports.createRequest = exports.getSigner = exports.signData = void 0;
var ethers_1 = require("ethers");
function signData(signer, types, values) {
    var message = ethers_1.utils.arrayify(ethers_1.utils.keccak256(ethers_1.utils.defaultAbiCoder.encode(types, values)));
    return signer.signMessage(message);
}
exports.signData = signData;
function getSigner(types, values, signature) {
    var message = ethers_1.utils.arrayify(ethers_1.utils.keccak256(ethers_1.utils.defaultAbiCoder.encode(types, values)));
    return ethers_1.utils.verifyMessage(message, signature);
}
exports.getSigner = getSigner;
function createRequest(owner, factor, handle, t) {
    return __awaiter(this, void 0, void 0, function () {
        var timestamp, sender, verifier;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    factor = ethers_1.utils.formatBytes32String(factor);
                    timestamp = (t === undefined) ? Math.floor(new Date().getTime() / 1000) : t;
                    return [4 /*yield*/, signData(owner, ['bytes32', 'uint'], [factor, timestamp])];
                case 1:
                    sender = _a.sent();
                    return [4 /*yield*/, signData(owner, ['bytes', 'string'], [sender, handle])];
                case 2:
                    verifier = _a.sent();
                    return [2 /*return*/, { factor: factor, timestamp: timestamp, sender: sender, handle: handle, verifier: verifier }];
            }
        });
    });
}
exports.createRequest = createRequest;
function encodeRequest(request) {
    var factor = request.factor, timestamp = request.timestamp, sender = request.sender, handle = request.handle, verifier = request.verifier;
    return btoa(JSON.stringify({ factor: factor, timestamp: timestamp, sender: btoa(sender), handle: handle, verifier: btoa(verifier) }));
}
exports.encodeRequest = encodeRequest;
function decodeRequest(encodedRequest) {
    var data = JSON.parse(atob(encodedRequest));
    data.sender = atob(data.sender);
    data.verifier = atob(data.verifier);
    return data;
}
exports.decodeRequest = decodeRequest;
function isDefined(value) {
    // match both null and undefined
    return !(value == null);
}
function checkToken(token) {
    return (isDefined(token));
}
function checkTimestamp(timestamp) {
    return (isDefined(timestamp) && !isNaN(timestamp) && ((new Date(timestamp * 1000)).getTime() > 0));
}
var ValidationError;
(function (ValidationError) {
    ValidationError["FACTOR_FORMAT_ERROR"] = "The factor is not valid";
    ValidationError["TIMESTAMP_FORMAT_ERROR"] = "The timestamp is not valid";
    ValidationError["HANDLE_FORMAT_ERROR"] = "The handle is not valid";
    ValidationError["INVALID_SENDER_SIGNATURE_ERROR"] = "The sender signature is not valid";
    ValidationError["INVALID_VERIFIER_SIGNATURE_ERROR"] = "The verifier signature is not valid";
    ValidationError["SIGNATURE_MISMATCH_ERROR"] = "The verifier and signer signature do not match to the same address";
    ValidationError["TOKEN_FORMAT_ERROR"] = "The token is not valid";
    ValidationError["OUTDATED_TIMESTAMP_ERROR"] = "The timestamp is outdated";
    ValidationError["POSTDATED_TIMESTAMP_ERROR"] = "The timestamp is post-dated (make sure your computer time is correct)";
    ValidationError["UNTRUSTED_VALIDATOR_ERROR"] = "The validator is not trusted";
    ValidationError["INVALID_VALIDATOR_SIGNATURE_ERROR"] = "The validator signature is not a valid signature";
})(ValidationError = exports.ValidationError || (exports.ValidationError = {}));
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
    var validateHandle = config.validateHandle, factors = config.factors, freshness = config.freshness;
    var factor = request.factor, timestamp = request.timestamp, sender = request.sender, handle = request.handle, verifier = request.verifier;
    var res = [];
    if (!checkFactor(factors, factor)) {
        res.push(ValidationError.FACTOR_FORMAT_ERROR);
    }
    if (!checkTimestamp(timestamp)) {
        res.push(ValidationError.TIMESTAMP_FORMAT_ERROR);
    }
    if (!validateHandle(handle)) {
        res.push(ValidationError.HANDLE_FORMAT_ERROR);
    }
    var now = Math.floor(new Date().getTime() / 1000);
    if (timestamp > now) {
        res.push(ValidationError.POSTDATED_TIMESTAMP_ERROR);
    }
    if ((freshness > 0) && (timestamp + freshness < now)) {
        res.push(ValidationError.OUTDATED_TIMESTAMP_ERROR);
    }
    var checkSender;
    try {
        checkSender = getSigner(['bytes32', 'uint'], [factor, timestamp], sender);
    }
    catch (e) {
        res.push(ValidationError.INVALID_SENDER_SIGNATURE_ERROR);
    }
    try {
        var checkVerifier = getSigner(['bytes', 'string'], [sender, handle], verifier);
        if (checkVerifier !== checkSender) {
            res.push(ValidationError.SIGNATURE_MISMATCH_ERROR);
        }
    }
    catch (e) {
        res.push(ValidationError.INVALID_VERIFIER_SIGNATURE_ERROR);
    }
    return res;
}
exports.checkRequest = checkRequest;
function createCredentials(config, request) {
    return __awaiter(this, void 0, void 0, function () {
        var factor, timestamp, sender, handle, verifier, key, token, validator;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    factor = request.factor, timestamp = request.timestamp, sender = request.sender, handle = request.handle, verifier = request.verifier;
                    key = new Uint8Array(Buffer.from(config.key, 'base64'));
                    token = ethers_1.utils.computeHmac(ethers_1.utils.SupportedAlgorithm.sha256, key, ethers_1.utils.keccak256(ethers_1.utils.solidityPack(["bytes32", "string"], [factor, handle])));
                    return [4 /*yield*/, signData(ethers_1.Wallet.fromMnemonic(config.mnemonic), ['bytes', 'bytes32'], [sender, token])];
                case 1:
                    validator = _a.sent();
                    return [2 /*return*/, { factor: factor, timestamp: timestamp, sender: sender, token: token, validator: validator }];
            }
        });
    });
}
exports.createCredentials = createCredentials;
function checkCredentials(config, credentials) {
    var factors = config.factors, isValid = config.isValid, freshness = config.freshness;
    var factor = credentials.factor, timestamp = credentials.timestamp, sender = credentials.sender, token = credentials.token, validator = credentials.validator;
    var res = [];
    if (!checkFactor(factors, factor)) {
        res.push(ValidationError.FACTOR_FORMAT_ERROR);
    }
    if (!checkToken(token)) {
        res.push(ValidationError.TOKEN_FORMAT_ERROR);
    }
    if (!checkTimestamp(timestamp)) {
        res.push(ValidationError.TIMESTAMP_FORMAT_ERROR);
    }
    var now = Math.floor(new Date().getTime() / 1000);
    if (timestamp > now) {
        res.push(ValidationError.POSTDATED_TIMESTAMP_ERROR);
    }
    if ((freshness > 0) && (timestamp + freshness < now)) {
        res.push(ValidationError.OUTDATED_TIMESTAMP_ERROR);
    }
    try {
        var senderCheck = getSigner(['bytes32', 'uint'], [factor, timestamp], sender);
    }
    catch (e) {
        res.push(ValidationError.INVALID_SENDER_SIGNATURE_ERROR);
    }
    try {
        var validatorCheck = getSigner(['bytes', 'bytes32'], [sender, token], validator);
        if (!isValid(validatorCheck)) {
            res.push(ValidationError.UNTRUSTED_VALIDATOR_ERROR);
        }
    }
    catch (e) {
        res.push(ValidationError.INVALID_VALIDATOR_SIGNATURE_ERROR);
    }
    return res;
}
exports.checkCredentials = checkCredentials;
function encodeCredentials(credentials) {
    var factor = credentials.factor, timestamp = credentials.timestamp, sender = credentials.sender, token = credentials.token, validator = credentials.validator;
    return btoa(JSON.stringify({ factor: factor, timestamp: timestamp, sender: btoa(sender), token: token, validator: btoa(validator) }));
}
exports.encodeCredentials = encodeCredentials;
function decodeCredentials(encodedCredentials) {
    var data = JSON.parse(atob(encodedCredentials));
    data.sender = atob(data.sender);
    data.validator = atob(data.validator);
    return data;
}
exports.decodeCredentials = decodeCredentials;
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
