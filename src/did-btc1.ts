import type {
  DidDocument,
  DidResolutionOptions,
  DidResolutionResult,
  DidVerificationMethod
} from '@web5/dids';
import { Did, DidError, DidErrorCode, DidMethod, EMPTY_DID_RESOLUTION_RESULT } from '@web5/dids';

export function extractDidFragment(input: unknown): string | undefined {
  if (typeof input !== 'string') return undefined;
  if (input.length === 0) return undefined;
  return input.split('#').pop();
}

export class DidBtc1 extends DidMethod {

  /**
   * Name of the DID method, as defined in the DID BTC1 specification.
   */
  public static methodName = 'btc1';

  /**
   * Given the W3C DID Document of a `did:btc1` DID, return the verification method that will be used
   * for signing messages and credentials. If given, the `methodId` parameter is used to select the
   * verification method. If not given, the Identity Key's verification method with an ID fragment
   * of '#0' is used.
   *
   * @param params - The parameters for the `getSigningMethod` operation.
   * @param params.didDocument - DID Document to get the verification method from.
   * @param params.methodId - ID of the verification method to use for signing.
   * @returns Verification method to use for signing.
   */
  public static async getSigningMethod({ didDocument, methodId = '#0' }: {
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