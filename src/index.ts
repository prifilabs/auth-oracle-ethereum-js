import { Signer, Wallet, utils } from "ethers";

export async function signData(signer:Signer, types:string[], values:any[]){
    let message = utils.arrayify(utils.keccak256(utils.defaultAbiCoder.encode(types, values)));
    return signer.signMessage(message);
}

export function getSigner(types:string[], values:any[], signature:string){
    let message = utils.arrayify(utils.keccak256(utils.defaultAbiCoder.encode(types, values)));
    return utils.verifyMessage(message, signature);
}

function isDefined(value:any){
    // match both null and undefined
    return !(value == null);
}

function checkAddress(address:string){
    return (isDefined(address) && utils.isAddress(address));
}

function checkToken(token:string){
    return (isDefined(token));
}

function checkTimestamp(timestamp:number){
    return (isDefined(timestamp) && !isNaN(timestamp) && ((new Date(timestamp * 1000)).getTime() > 0));
}

export const validationErrors = {
    SENDER_FORMAT_ERROR: "The sender is not a valid address",
    SIGNER_FORMAT_ERROR: "The signer is not a valid address",
    FACTOR_FORMAT_ERROR: "The factor is not a valid factor",
    TOKEN_FORMAT_ERROR: "The factor is not a valid bytes32",
    TIMESTAMP_FORMAT_ERROR: "The timestamp is not a valid date",
    HANDLE_FORMAT_ERROR: "The handle is not a valid string",
    INVALID_SIGNATURE: "The signature is invalid",
    UNTRUSTED_SIGNER_ERROR: "The signer is not trusted",
    REVOKED_SIGNER_ERROR: "The signer has been revoked",
}

function checkFactor(factors:string[], factor:string){
    try{
        let f = utils.parseBytes32String(factor);
        return (factors.indexOf(f) > -1);
    } catch(e){
        return false;
    }
}

export interface CheckRequestConfig {
    validateHandle: (handle:string) => boolean;
    factors: string[];
}

export interface Request{
    sender:string;
    factor:string;
    handle:string;
    signature:string;
}

export async function checkRequest(config:CheckRequestConfig, request:Request){
    let { validateHandle, factors } = config;
    let { sender, factor, handle, signature } = request;
    let res = [];
    if (!checkAddress(sender)) { res.push('SENDER_FORMAT_ERROR');}
    if (!checkFactor(factors, factor)) { res.push('FACTOR_FORMAT_ERROR');}
    if (!validateHandle(handle)) { res.push('HANDLE_FORMAT_ERROR');}
    let senderCheck;
    try{
        senderCheck = getSigner(['address', 'bytes32', 'string'], [sender, factor, handle], signature);
        if (senderCheck !== sender) { res.push('INVALID_SIGNATURE'); }
    } catch (e){
        res.push('INVALID_SIGNATURE');
    }
    return res;
}

export interface CheckCredentialsConfig {
    factors: string[];
    isValid: (address:string) => boolean;
    isRevoked: (address:string) => number;
}

export interface Credentials {
    sender:string;
    signer: string;
    factor:string;
    token: string;
    timestamp:number;
    signature:string;
}

export async function checkCredentials(config:CheckCredentialsConfig, credentials:Credentials){
    let {factors, isValid, isRevoked} = config;
    let {sender, signer, factor, token , timestamp, signature} = credentials;
    let res = [];
    if (!checkAddress(sender)) { res.push('SENDER_FORMAT_ERROR');}
    if (!checkAddress(signer)) { res.push('SIGNER_FORMAT_ERROR');}
    if (!checkFactor(factors, factor)) { res.push('FACTOR_FORMAT_ERROR');}
    if (!checkToken(token)) { res.push('TOKEN_FORMAT_ERROR');}
    if (!checkTimestamp(timestamp)) { res.push('TIMESTAMP_FORMAT_ERROR');}
    if (!isValid(signer)) { res.push('UNTRUSTED_SIGNER_ERROR'); }
    let t = isRevoked(signer);
    if ((t!==0) && (timestamp > t)) { res.push('REVOKED_SIGNER_ERROR'); }
    let signerCheck;
    try{
        signerCheck = getSigner(['address', 'address', 'bytes32', 'bytes32', 'uint'], [sender, signer, factor, token, timestamp], signature);
        if (signerCheck !== signer) { res.push('INVALID_SIGNATURE'); }
    } catch (e){
        res.push('INVALID_SIGNATURE');
    }
    return res;
}

export async function createRequest(signer:Signer, factor:string, handle:string){
    factor = utils.formatBytes32String(factor);
    let types = ['address', 'bytes32', 'string'];
    let sender = await signer.getAddress();
    let values = [sender, factor, handle];
    let signature = await signData(signer, types, values);
    return {sender, factor, handle, signature};
}

interface CreateCredentialsConfig {
    key:string;
    mnemonic: string;
    time?: number;
}

export async function createCredentials(config:CreateCredentialsConfig, request: Request){
      let {sender, factor, handle, signature} = request;
      let key = new Uint8Array(Buffer.from(config.key, 'base64'));
      let token = utils.computeHmac( utils.SupportedAlgorithm.sha256 , key , utils.keccak256(utils.solidityPack(["bytes32", "string"], [factor, handle])));
      let timestamp = (config?.time)? config.time : Math.floor(new Date().getTime() / 1000);
      let validator = Wallet.fromMnemonic(config.mnemonic);
      let signer = await validator.getAddress();
      let sig = await signData(validator, ['address', 'address', 'bytes32', 'bytes32', 'uint'], [sender, signer, factor, token, timestamp]);
      let credentials = {sender, signer, factor, token, timestamp, signature: btoa(sig)};
      let encodedCredentials = btoa(JSON.stringify(credentials));
      return encodedCredentials;
}

export function decodeCredentials(encodedCredentials:string){
    let data = JSON.parse(atob(encodedCredentials));
    data.signature = atob(data.signature);
    return data;
};

export async function createSecrets (){
    const mnemonic = await Wallet.createRandom().mnemonic.phrase;
    const rd = utils.randomBytes(32);
    const key = Buffer.from(rd).toString('base64');
    return { mnemonic, key };
}
