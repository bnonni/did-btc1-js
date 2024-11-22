import { DidCreateOptions, DidCreateVerificationMethod, DidDocument, DidService } from '@web5/dids';

export enum DidBtc1RegisteredKeyType {
    /**
     * secp256k1: A cryptographic curve used for digital signatures in a range of decentralized
     * systems.
     */
    secp256k1 = 1,
}

export enum DidBtc1Network {
    mainnet = 'mainnet',
    testnet = 'testnet',
    signet = 'signet',
    regtest = 'regtest',
}
/**
 * Options for creating a Decentralized Identifier (DID) using the DID BTC1 method.
 */
export interface DidBtc1CreateOptions<TKms> extends DidCreateOptions<TKms> {
    version?: number;
    purpose?: string;
    network?: 'mainnet' | 'testnet' | 'signet' | 'regtest';
    /**
     * Optional. An array of service endpoints associated with the DID.
     *
     * Services are used in DID documents to express ways of communicating with the DID subject or
     * associated entities. A service can be any type of service the DID subject wants to advertise,
     * including decentralized identity management services for further discovery, authentication,
     * authorization, or interaction.
     *
     * @see {@link https://www.w3.org/TR/did-core/#services | DID Core Specification, § Services}
     *
     * @example
     * ```ts
     * const did = await DidBtc1.create({
     *  options: {
     *   services: [
     *     {
     *       id: '#singletonBeacon',
     *       type: 'SingletonBeacon',
     *       serviceEndpoint: 'bitcoin:some-funded-address',
     *     }
     *   ]
     * };
     * ```
     */
    services?: DidService[];

    /**
     * Optional. An array of verification methods to be included in the DID document.
     *
     * By default, a newly created DID BTC1 document will contain a single Secp256k1 verification method.
     *
     * @see {@link https://www.w3.org/TR/did-core/#verification-methods | DID Core Specification, § Verification Methods}
     *
     * @example
     * ```ts
     * const did = await DidBtc1.create({
     *  options: {
     *     {
     *       id: '#initialKey',
     *       type: 'JsonWebKey',
     *     }
     *   ]
     * };
     * ```
     */
    verificationMethods?: DidCreateVerificationMethod<TKms>[];
}

export type DidBtc1CreateResponse = { mnemonic: string; didDocument: DidDocument; };
