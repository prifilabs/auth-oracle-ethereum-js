import { Signer } from "ethers";
export declare function signData(signer: Signer, types: string[], values: any[]): Promise<string>;
export declare function getSigner(types: string[], values: any[], signature: string): string;
export interface Request {
    factor: string;
    timestamp: number;
    sender: string;
    handle: string;
    verifier: string;
}
export declare function createRequest(owner: Signer, factor: string, handle: string, t?: number): Promise<Request>;
export declare function encodeRequest(request: Request): string;
export declare function decodeRequest(encodedRequest: string): Request;
export declare enum ValidationError {
    FACTOR_FORMAT_ERROR = "The factor is not valid",
    TIMESTAMP_FORMAT_ERROR = "The timestamp is not valid",
    HANDLE_FORMAT_ERROR = "The handle is not valid",
    INVALID_SENDER_SIGNATURE_ERROR = "The sender signature is not valid",
    INVALID_VERIFIER_SIGNATURE_ERROR = "The verifier signature is not valid",
    SIGNATURE_MISMATCH_ERROR = "The verifier and signer signature do not match to the same address",
    TOKEN_FORMAT_ERROR = "The token is not valid",
    OUTDATED_TIMESTAMP_ERROR = "The timestamp is outdated",
    POSTDATED_TIMESTAMP_ERROR = "The timestamp is post-dated (make sure your computer time is correct)",
    UNTRUSTED_VALIDATOR_ERROR = "The validator is not trusted",
    INVALID_VALIDATOR_SIGNATURE_ERROR = "The validator signature is not a valid signature"
}
export interface CheckRequestConfig {
    validateHandle: (handle: string) => boolean;
    factors: string[];
    freshness: number;
}
export declare function checkRequest(config: CheckRequestConfig, request: Request): ValidationError[];
export interface Credentials {
    factor: string;
    timestamp: number;
    sender: string;
    token: string;
    validator: string;
}
interface CreateCredentialsConfig {
    key: string;
    mnemonic: string;
    time?: number;
}
export declare function createCredentials(config: CreateCredentialsConfig, request: Request): Promise<Credentials>;
export interface CheckCredentialsConfig {
    factors: string[];
    isValid: (address: string) => boolean;
    freshness: number;
}
export declare function checkCredentials(config: CheckCredentialsConfig, credentials: Credentials): ValidationError[];
export declare function encodeCredentials(credentials: Credentials): string;
export declare function decodeCredentials(encodedCredentials: string): Credentials;
export declare function createSecrets(): Promise<{
    mnemonic: string;
    key: string;
}>;
export {};
