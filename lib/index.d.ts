import { Signer } from "ethers";
export declare function signData(signer: Signer, types: string[], values: any[]): Promise<string>;
export declare function getSigner(types: string[], values: any[], signature: string): string;
export declare const validationErrors: {
    SENDER_FORMAT_ERROR: string;
    SIGNER_FORMAT_ERROR: string;
    FACTOR_FORMAT_ERROR: string;
    TOKEN_FORMAT_ERROR: string;
    TIMESTAMP_FORMAT_ERROR: string;
    HANDLE_FORMAT_ERROR: string;
    INVALID_SIGNATURE: string;
    UNTRUSTED_SIGNER_ERROR: string;
    REVOKED_SIGNER_ERROR: string;
};
export interface CheckRequestConfig {
    validateHandle: (handle: string) => boolean;
    factors: string[];
}
export interface Request {
    sender: string;
    factor: string;
    handle: string;
    signature: string;
}
export declare function checkRequest(config: CheckRequestConfig, request: Request): Promise<any[]>;
export interface CheckCredentialsConfig {
    factors: string[];
    isValid: (address: string) => boolean;
    isRevoked: (address: string) => number;
}
export interface Credentials {
    sender: string;
    signer: string;
    factor: string;
    token: string;
    timestamp: number;
    signature: string;
}
export declare function checkCredentials(config: CheckCredentialsConfig, credentials: Credentials): Promise<any[]>;
export declare function createRequest(signer: Signer, factor: string, handle: string): Promise<{
    sender: string;
    factor: string;
    handle: string;
    signature: string;
}>;
interface CreateCredentialsConfig {
    key: string;
    mnemonic: string;
    time?: number;
}
export declare function createCredentials(config: CreateCredentialsConfig, request: Request): Promise<string>;
export declare function decodeCredentials(encodedCredentials: string): any;
export declare function createSecrets(): Promise<{
    mnemonic: string;
    key: string;
}>;
export {};
