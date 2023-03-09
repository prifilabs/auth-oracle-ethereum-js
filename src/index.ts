import { Signer, Wallet, utils } from "ethers";

export function signData(signer:Signer, types:string[], values:any[]){
    let message = utils.arrayify(utils.keccak256(utils.defaultAbiCoder.encode(types, values)));
    return signer.signMessage(message);
}

export function getSigner(types:string[], values:any[], signature:string){
    let message = utils.arrayify(utils.keccak256(utils.defaultAbiCoder.encode(types, values)));
    return utils.verifyMessage(message, signature);
}

export interface Request{
    factor:string;
    timestamp:number;
    sender: string;
    handle:string;
    verifier:string;
}

export async function createRequest(owner:Signer, factor:string, handle:string, t?:number): Promise<Request>{
    factor = utils.formatBytes32String(factor);
    let timestamp = (t === undefined)?  Math.floor(new Date().getTime() / 1000) : t;
    let sender = await signData(owner, ['bytes32', 'uint'], [factor, timestamp]);
    let verifier = await signData(owner, ['bytes', 'string'], [sender, handle]);
    return {factor, timestamp, sender, handle, verifier};
}

export function encodeRequest(request: Request):string{
      const {factor, timestamp, sender, handle, verifier} = request;
      return btoa(JSON.stringify({factor, timestamp, sender:btoa(sender), handle, verifier:btoa(verifier)}));
}

export function decodeRequest(encodedRequest:string):Request{
    let data = JSON.parse(atob(encodedRequest));
    data.sender = atob(data.sender);
    data.verifier = atob(data.verifier);
    return data;
}

function isDefined(value:any):boolean{
    // match both null and undefined
    return !(value == null);
}

function checkToken(token:string):boolean{
    return (isDefined(token));
}

function checkTimestamp(timestamp:number):boolean{
    return (isDefined(timestamp) && !isNaN(timestamp) && ((new Date(timestamp * 1000)).getTime() > 0));
}

export enum ValidationError {
    FACTOR_FORMAT_ERROR = "The factor is not valid",
    TIMESTAMP_FORMAT_ERROR = "The timestamp is not valid",
    HANDLE_FORMAT_ERROR = "The handle is not valid",
    INVALID_SENDER_SIGNATURE_ERROR = "The sender signature is not valid",
    INVALID_VERIFIER_SIGNATURE_ERROR = "The verifier signature is not valid",
    SIGNATURE_MISMATCH_ERROR = "The verifier and signer signature do not match to the same address",
    TOKEN_FORMAT_ERROR= "The token is not valid",
    OUTDATED_TIMESTAMP_ERROR = "The timestamp is outdated",
    POSTDATED_TIMESTAMP_ERROR = "The timestamp is post-dated (make sure your computer time is correct)",
    UNTRUSTED_VALIDATOR_ERROR = "The validator is not trusted",
    INVALID_VALIDATOR_SIGNATURE_ERROR = "The validator signature is not a valid signature",
}

function checkFactor(factors:string[], factor:string):boolean{
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
    freshness: number;
}

export function checkRequest(config:CheckRequestConfig, request:Request):ValidationError[]{
    let { validateHandle, factors, freshness} = config;
    let { factor, timestamp, sender, handle, verifier } = request;
    let res = [];
    if (!checkFactor(factors, factor)) { res.push(ValidationError.FACTOR_FORMAT_ERROR);}
    if (!checkTimestamp(timestamp)) { res.push(ValidationError.TIMESTAMP_FORMAT_ERROR);}
    if (!validateHandle(handle)) { res.push(ValidationError.HANDLE_FORMAT_ERROR);}
    let now = Math.floor(new Date().getTime() / 1000);
    if (timestamp > now) { res.push(ValidationError.POSTDATED_TIMESTAMP_ERROR); }
    if ((freshness > 0) && (timestamp + freshness < now)) { res.push(ValidationError.OUTDATED_TIMESTAMP_ERROR); }
    let checkSender;
    try{
        checkSender = getSigner(['bytes32', 'uint'], [factor, timestamp], sender);
    } catch (e){
        res.push(ValidationError.INVALID_SENDER_SIGNATURE_ERROR);
    }
    try{
        let checkVerifier = getSigner(['bytes', 'string'], [sender, handle], verifier);
        if (checkVerifier !== checkSender) {res.push(ValidationError.SIGNATURE_MISMATCH_ERROR)}
    } catch (e){
        res.push(ValidationError.INVALID_VERIFIER_SIGNATURE_ERROR);
    }
    return res;
}

export interface Credentials {
    factor:string;
    timestamp:number;
    sender: string;
    token: string;
    validator:string;
}

interface CreateCredentialsConfig {
    key:string;
    mnemonic: string;
    time?: number;
}

export async function createCredentials(config:CreateCredentialsConfig, request: Request): Promise<Credentials>{
      let {factor, timestamp, sender, handle, verifier} = request;
      let key = new Uint8Array(Buffer.from(config.key, 'base64'));
      let token = utils.computeHmac( utils.SupportedAlgorithm.sha256 , key , utils.keccak256(utils.solidityPack(["bytes32", "string"], [factor, handle])));
      let validator = await signData(Wallet.fromMnemonic(config.mnemonic), ['bytes', 'bytes32'], [sender, token]);
      return {factor, timestamp, sender, token, validator};
}

export interface CheckCredentialsConfig {
    factors: string[];
    isValid: (address:string) => boolean;
    freshness: number;
}

export function checkCredentials(config:CheckCredentialsConfig, credentials:Credentials): ValidationError[]{
    let {factors, isValid, freshness} = config;
    let {factor, timestamp, sender, token, validator} = credentials;
    let res = [];
    if (!checkFactor(factors, factor)) { res.push(ValidationError.FACTOR_FORMAT_ERROR);}
    if (!checkToken(token)) { res.push(ValidationError.TOKEN_FORMAT_ERROR);}
    if (!checkTimestamp(timestamp)) { res.push(ValidationError.TIMESTAMP_FORMAT_ERROR);}
    let now = Math.floor(new Date().getTime() / 1000);
    if (timestamp > now) { res.push(ValidationError.POSTDATED_TIMESTAMP_ERROR); }
    if ((freshness > 0) && (timestamp + freshness < now)) { res.push(ValidationError.OUTDATED_TIMESTAMP_ERROR); }
    try{
        let senderCheck = getSigner(['bytes32', 'uint'], [factor, timestamp], sender);
    } catch (e){
        res.push(ValidationError.INVALID_SENDER_SIGNATURE_ERROR);
    }
    try{
        let validatorCheck = getSigner(['bytes', 'bytes32'], [sender, token], validator);
        if (!isValid(validatorCheck)) { res.push(ValidationError.UNTRUSTED_VALIDATOR_ERROR); }
    } catch (e){
        res.push(ValidationError.INVALID_VALIDATOR_SIGNATURE_ERROR);
    }
    return res;
}

export function encodeCredentials(credentials:Credentials): string{
      const {factor, timestamp, sender, token, validator} = credentials;
      return btoa(JSON.stringify({factor, timestamp, sender:btoa(sender), token, validator:btoa(validator)}));
}

export function decodeCredentials(encodedCredentials:string): Credentials{
    let data = JSON.parse(atob(encodedCredentials));
    data.sender = atob(data.sender);
    data.validator = atob(data.validator);
    return data;
}

export async function createSecrets (){
    const mnemonic = await Wallet.createRandom().mnemonic.phrase;
    const rd = utils.randomBytes(32);
    const key = Buffer.from(rd).toString('base64');
    return { mnemonic, key };
}
