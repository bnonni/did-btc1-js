import * as secp256k1 from '@noble/secp256k1';
import { base58, base64url, bech32 } from '@scure/base';
import { HDKey } from '@scure/bip32';
import { generateMnemonic, mnemonicToSeed } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { Jwk, LocalKeyManager } from '@web5/crypto';
import type {
  DidDocument,
  DidResolutionOptions,
  DidResolutionResult,
  DidVerificationMethod
} from '@web5/dids';
import {
  Did,
  DidError,
  DidErrorCode,
  DidMethod,
  EMPTY_DID_RESOLUTION_RESULT
} from '@web5/dids';
import { initEccLib, Network, networks, payments } from 'bitcoinjs-lib';
import { Logger } from 'scclogger';
import * as ecc from 'tiny-secp256k1';
import {
  DidBtc1BeaconService,
  DidBtc1CreateOptions,
  DidBtc1CreateResponse,
  DidBtc1DocumentCreateOptions,
  DidBtc1Network,
  DidBtc1RegisteredKeyType
} from './types.js';
import { bigintToBuffer, extractDidFragment } from './utils.js';
initEccLib(ecc);
const AlgorithmToKeyTypeMap = { secp256k1: DidBtc1RegisteredKeyType.secp256k1 } as const;

export class DidBtc1 extends DidMethod {
  /**
   * Name of the DID method, as defined in the DID BTC1 specification.
   */
  public static methodName = 'btc1';

  /**
   *
   * @param params.keyManager - The key manager to use for key operations.
   * @param params.options - Optional parameters for creating the DID. See {@link DidBtc1CreateOptions}.
   * @returns A Promise resolving to a {@link DidBtc1CreateResponse} object containing the mnemonic
   */
  public static async create({
    keyManager = new LocalKeyManager(),
    options = {}
  }: {
    keyManager?: LocalKeyManager;
    options?: DidBtc1CreateOptions<LocalKeyManager>;
  } = {}): Promise<DidBtc1CreateResponse> {
    // Before processing the create operation, validate DID-method-specific requirements to prevent
    // keys from being generated unnecessarily.

    // Check 1: Validate that the algorithm for any given verification method is supported by the
    // DID BTC1 specification.
    if (options.verificationMethods?.some(vm => !(vm.algorithm in AlgorithmToKeyTypeMap))) {
      throw new Error('One or more verification method algorithms are not supported');
    }

    // Check 2: Validate that the ID for any given verification method is unique.
    const methodIds = options.verificationMethods?.filter(vm => 'id' in vm).map(vm => vm.id);
    if (methodIds && methodIds.length !== new Set(methodIds).size) {
      throw new Error('One or more verification method IDs are not unique');
    }

    // Check 3: Validate that the required properties for any given services are present.
    if (options.services?.some(s => !s.id || !s.type || !s.serviceEndpoint)) {
      throw new Error('One or more services are missing required properties');
    }

    // Check 4: Validate that the network is one of enum DidBtc1Network.
    if(options.network && !(options.network in DidBtc1Network)) {
      throw new Error(`Invalid network: ${options.network}`);
    }

    // Set the version to the default value if not provided.
    const version = options.version ?? 1;

    // Set the did version to the default value if not provided.
    const v1 = version === 1;

    // Set the purpose to the default value if not provided.
    const purpose = options.purpose ?? '44';

    // Set the networkName to the default value if not provided.
    const networkName = options.network ?? 'mainnet';

    // Set the network object class based on the options above.
    const network = networkName === 'mainnet' ? networks.bitcoin : options.network === 'regtest' ? networks.regtest : networks.testnet;

    // Set the coin based on the network.
    const coin = networkName === 'mainnet' ? 0 : 1;

    // Set the derivation path based on the options above.
    const derivationPath = `m/${purpose}'/${coin}'/0'/0/0`;

    // Generate random mnemonic.
    const mnemonic = generateMnemonic(wordlist, 128);

    // Generate seed from mnemonic.
    const seed = await mnemonicToSeed(mnemonic);

    // Generate HDKey from seed.
    const hdkey = HDKey.fromMasterSeed(seed).derive(derivationPath);

    // Ensure HDKeys are valid
    if (!(hdkey.publicKey && hdkey.privateKey)) {
      throw new Error('Failed to derive hd key');
    }

    // Set a publicKey var from the hdkey.
    const publicKey = hdkey.publicKey;

    // Get x, y points from public key.
    const { x, y } = secp256k1.ProjectivePoint.fromHex(publicKey) ?? {};

    // Set the hrp based on the network.
    const hrp = networkName === 'mainnet' ? 'bc' : 'tb';

    // Bech32 encode the public key.
    const methodSpecificId = bech32.encode(hrp, bech32.toWords(publicKey));

    const isDeterministic = options.creationType === 'deterministic';

    const key = isDeterministic
      ? publicKey
      : {
        kty : 'EC',
        crv : 'secp256k1',
        x   : base64url.encode(bigintToBuffer(x)),
        y   : base64url.encode(bigintToBuffer(y)),
        d   : base64url.encode(Buffer.from(hdkey.privateKey))
      };

    if(!isDeterministic) {
      // Import key to key manager.
      const keyUri = await keyManager.importKey({ key: key as Jwk });
      Logger.log('DidBtc1 Key Imported', keyUri);
    }

    // Create DID Method prefix based on version.
    const didMethodPrefix = !v1
      ? `did:${this.methodName}:${version}:k1`
      : `did:${this.methodName}:k1`;

    // Create DID from method prefix and method specific ID.
    const did = `${didMethodPrefix}:${methodSpecificId}`;

    // Set the beaconType, creationType, verificationMethodType based on the options above.
    const beaconType = options.beaconType ?? 'SingletonBeacon';
    const creationType = options.creationType ?? 'deterministic';
    const verificationMethodType = options.verificationMethodType ?? 'SchnorrSecp256k1VerificationKey2024';

    const didDocument = this.createDidDocument({ did, key, options: { network, beaconType, creationType, verificationMethodType }});

    // Return mnemonic and DID Document.
    return { mnemonic, didDocument };
  }

  public static generateBeaconService({ pubkey, network, addressType }: { pubkey: Uint8Array, network: Network, addressType: string }): DidBtc1BeaconService {
    const beaconService: Partial<DidBtc1BeaconService> = {
      id              : `#initial_${addressType}`,
      type            : 'SingletonBeacon',
    };
    switch(addressType) {
      case 'p2pkh':
        beaconService.serviceEndpoint = `bitcoin:${payments.p2pkh({ pubkey, network }).address}`;
        return beaconService as DidBtc1BeaconService;
      case 'p2wpkh':
        beaconService.serviceEndpoint = `bitcoin:${payments.p2pkh({ pubkey, network }).address}`;
        return beaconService as DidBtc1BeaconService;
      case 'p2tr':
        beaconService.serviceEndpoint = `bitcoin:${payments.p2tr({ pubkey, network }).address}`;
        return beaconService as DidBtc1BeaconService;
      default:
        throw new Error(`Invalid address type: ${addressType}`);
    }
  }

  public static createDidDocument({ did, key, options }: { did: string, key: any, options: DidBtc1DocumentCreateOptions }): DidDocument {
    const initialDidDoc: Partial<DidDocument> = {
      '@context'           : [
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/data-integrity/v2',
        'https://github.com/dcdpr/did-btc1'
      ],
    };

    return options.creationType === 'deterministic'
      ? {
        ...initialDidDoc,
        id                   : did,
        authentication       : ['#initialKey'],
        assertionMethod      : ['#initialKey'],
        capabilityInvocation : ['#initialKey'],
        capabilityDelegation : ['#initialKey'],
        verificationMethod   : [{
          id                 : '#initialKey',
          controller         : did,
          type               : options.verificationMethodType,
          publicKeyMultibase : `z${base58.encode(key as Uint8Array)}`
        }],
      } : {
        ...initialDidDoc,
        id                   : did,
        verificationMethod   : [{
          controller   : did,
          publicKeyJwk : key,
          id           : '#initialKey',
          type         : options.verificationMethodType,
        }],
        service : [this.generateBeaconService({ pubkey: key, network: options.network, addressType: 'p2pkh' })]
      };
  }

  /**
   * Given the W3C DID Document of a `did:btc1` DID, return the verification method that will be used
   * for signing messages and credentials. If given, the `methodId` parameter is used to select the
   * verification method. If not given, the Identity Key's verification method with an ID fragment
   * of '#initialKey' is used.
   *
   * @param params - The parameters for the `getSigningMethod` operation.
   * @param params.didDocument - DID Document to get the verification method from.
   * @param params.methodId - ID of the verification method to use for signing.
   * @returns Verification method to use for signing.
   */
  public static async getSigningMethod({ didDocument, methodId = '#initialKey' }: {
    didDocument: DidDocument;
    methodId?: string;
  }): Promise<DidVerificationMethod> {
    // Verify the DID method is supported.
    const parsedDid = Did.parse(didDocument.id);
    if (parsedDid && parsedDid.method !== this.methodName) {
      throw new DidError(DidErrorCode.MethodNotSupported, `Method not supported: ${parsedDid.method}`);
    }

    // Attempt to find a verification method that matches the given method ID, or if not given,
    // find the first verification method intended for signing claims.
    const verificationMethod = didDocument.verificationMethod?.find(
      vm => extractDidFragment(vm.id) === (extractDidFragment(methodId) ?? extractDidFragment(didDocument.assertionMethod?.[0]))
    );
    if (!(verificationMethod && verificationMethod.publicKeyJwk)) {
      throw new DidError(DidErrorCode.InternalError, 'A verification method intended for signing could not be determined from the DID Document');
    }

    return verificationMethod;
  }
  /**
   * TODO: Implement create method.
   */

  /**
   * TODO: Implement resolve method.
   *
   * Resolves a `did:btc1` identifier to its corresponding DID document.
   *
   * This method performs the resolution of a `did:btc1` DID, retrieving its DID Document.
   *
   * @example
   * ```ts
   * const resolutionResult = await DidBtc1.resolve('did:btc1:example');
   * ```
   *
   * @param identifier - The DID to be resolved.
   * @param options - Optional parameters for resolving the DID. Unused by this DID method.
   * @returns A Promise resolving to a {@link DidResolutionResult} object representing the result of
   *          the resolution.
   */
  public static async resolve(identifier: string, options: DidResolutionOptions = {}): Promise<DidResolutionResult> {
    // To execute the read method operation, use the given gateway URI or a default.
    const aggregatorUri = options?.aggregatorUri ?? '<DEFAULT_AGGREGATOR_URI>';
    // const network = options?.network ?? '<DEFAULT_NETWORK>';
    // const cidBytes = bech32.decode(identifier);
    try {
      throw new Error('Not implemented: ' + aggregatorUri);
    } catch (error: any) {
      // Rethrow any unexpected errors that are not a `DidError`.
      if (!(error instanceof DidError)) throw new Error(error);

      // Return a DID Resolution Result with the appropriate error code.
      return {
        ...EMPTY_DID_RESOLUTION_RESULT,
        didResolutionMetadata : {
          error : error.code,
          ...error.message && { errorMessage: error.message }
        }
      };
    }
  }
}