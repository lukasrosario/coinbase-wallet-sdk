import EventEmitter from 'eventemitter3';
import { encodeAbiParameters, Hex, numberToHex, WalletGrantPermissionsParameters } from 'viem';

import { standardErrorCodes, standardErrors } from './core/error';
import { serializeError } from './core/error/serialize';
import {
  AppMetadata,
  ConstructorOptions,
  Preference,
  ProviderInterface,
  RequestArguments,
} from './core/provider/interface';
import { AddressString, Chain } from './core/type';
import { areAddressArraysEqual, hexStringFromNumber } from './core/type/util';
import { Signer } from './sign/interface';
import { createSigner, fetchSignerType, loadSignerType, storeSignerType } from './sign/util';
import {
  checkErrorForInvalidRequestArgs,
  fetchRPCRequest,
  fetchSessionKeyRPCRequest,
} from './util/provider';
import { Communicator } from ':core/communicator/Communicator';
import { SignerType } from ':core/message';
import { determineMethodCategory, SendCallsParams } from ':core/provider/method';
import { signWithPasskey } from ':util/passkeySigning';
import { ScopedLocalStorage } from ':util/ScopedLocalStorage';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { createCredential } = require('webauthn-p256');

export class CoinbaseWalletProvider extends EventEmitter implements ProviderInterface {
  private readonly metadata: AppMetadata;
  private readonly preference: Preference;
  private readonly communicator: Communicator;

  private signer: Signer | null;
  protected accounts: AddressString[] = [];
  protected chain: Chain;
  lastCredentialId?: string;

  constructor({ metadata, preference: { keysUrl, ...preference } }: Readonly<ConstructorOptions>) {
    super();
    this.metadata = metadata;
    this.preference = preference;
    this.communicator = new Communicator(keysUrl);
    this.chain = {
      id: metadata.appChainIds?.[0] ?? 1,
    };
    // Load states from storage
    const signerType = loadSignerType();
    this.signer = signerType ? this.initSigner(signerType) : null;
  }

  public get connected() {
    return this.accounts.length > 0;
  }

  public async request<T>(args: RequestArguments): Promise<T> {
    try {
      checkErrorForInvalidRequestArgs(args);
      // unrecognized methods are treated as fetch requests
      const category = determineMethodCategory(args.method) ?? 'fetch';
      return this.handlers[category](args) as T;
    } catch (error) {
      this.handleUnauthorizedError(error);
      return Promise.reject(serializeError(error, args.method));
    }
  }

  protected readonly handlers = {
    // eth_requestAccounts
    handshake: async (args: RequestArguments): Promise<any> => {
      if (this.connected) {
        this.emit('connect', { chainId: hexStringFromNumber(this.chain.id) });
        return { addresses: this.accounts };
      }

      const requests = (args.params as { requests: any }).requests as (
        | {
            method: 'wallet_grantPermissions';
            params: WalletGrantPermissionsParameters;
          }
        | { method: 'personal_sign'; params: [Hex] }
      )[];

      const credential = await createCredential({ name: '[DEMO APP]' });
      this.lastCredentialId = credential.id;

      const encodedPublicKey = encodeAbiParameters(
        [
          { name: 'x', type: 'uint256' },
          { name: 'y', type: 'uint256' },
        ],
        [credential.publicKey.x, credential.publicKey.y]
      );

      const updatedRequests = await Promise.all(
        requests.map(async (request) => {
          if (request.method === 'wallet_grantPermissions') {
            if (request.params.signer?.type === 'wallet') {
              return {
                ...request,
                params: {
                  ...request.params,
                  signer: {
                    type: 'passkey',
                    data: {
                      publicKey: encodedPublicKey,
                      credentialId: credential.id,
                    },
                  },
                },
              };
            }
          }
          return request;
        })
      );

      const signerType = await this.requestSignerSelection();
      const signer = this.initSigner(signerType);
      const accounts = await signer.handshake({ requests: updatedRequests });

      this.signer = signer;
      storeSignerType(signerType);

      this.emit('connect', { chainId: hexStringFromNumber(this.chain.id) });
      return accounts;
    },

    sign: async (request: RequestArguments) => {
      if (!this.connected || !this.signer) {
        throw standardErrors.provider.unauthorized(
          "Must call 'eth_requestAccounts' before other methods"
        );
      }
      return await this.signer.request(request);
    },

    fetch: (request: RequestArguments) => fetchRPCRequest(request, this.chain),

    signOrFetch: async (request: RequestArguments) => {
      if (!this.connected || !this.signer) {
        throw standardErrors.provider.unauthorized(
          "Must call 'eth_requestAccounts' before other methods"
        );
      }
      if (request.method === 'wallet_sendCalls') {
        const params = (request.params as SendCallsParams)[0];
        const hasPermissionsContext = !!params.capabilities?.permissions?.context;
        if (hasPermissionsContext) {
          const result = await fetchSessionKeyRPCRequest({
            ...request,
            method: 'wallet_fillUserOp',
          });
          if (!result.userOp || !result.hash) {
            throw standardErrors.rpc.internal('Failed to fill user op');
          }
          const { authenticatorData, clientDataJSON, signature } = await signWithPasskey(
            result.hash,
            this.lastCredentialId as string
          );
          const callsId = await fetchSessionKeyRPCRequest({
            method: 'wallet_sendUserOpWithSignature',
            params: {
              chainId: numberToHex(this.chain.id),
              userOp: result.userOp,
              signature: {
                authenticatorData,
                clientDataJSON,
                signature,
              },
            },
          });
          return callsId;
        }
        return await this.signer.request(request);
      }
      throw standardErrors.provider.unsupportedMethod();
    },

    state: (request: RequestArguments) => {
      const getConnectedAccounts = (): AddressString[] => {
        if (this.connected) return this.accounts;
        throw standardErrors.provider.unauthorized(
          "Must call 'eth_requestAccounts' before other methods"
        );
      };
      switch (request.method) {
        case 'eth_chainId':
          return hexStringFromNumber(this.chain.id);
        case 'net_version':
          return this.chain.id;
        case 'eth_accounts':
          return getConnectedAccounts();
        case 'eth_coinbase':
          return getConnectedAccounts()[0];
        default:
          return this.handlers.unsupported(request);
      }
    },

    deprecated: ({ method }: RequestArguments) => {
      throw standardErrors.rpc.methodNotSupported(`Method ${method} is deprecated.`);
    },

    unsupported: ({ method }: RequestArguments) => {
      throw standardErrors.rpc.methodNotSupported(`Method ${method} is not supported.`);
    },
  };

  private handleUnauthorizedError(error: unknown) {
    const e = error as { code?: number };
    if (e.code === standardErrorCodes.provider.unauthorized) this.disconnect();
  }

  /** @deprecated Use `.request({ method: 'eth_requestAccounts' })` instead. */
  public async enable(): Promise<unknown> {
    console.warn(
      `.enable() has been deprecated. Please use .request({ method: "eth_requestAccounts" }) instead.`
    );
    return await this.request({
      method: 'eth_requestAccounts',
    });
  }

  async disconnect(): Promise<void> {
    this.accounts = [];
    this.chain = { id: 1 };
    this.signer?.disconnect();
    ScopedLocalStorage.clearAll();
    this.emit('disconnect', standardErrors.provider.disconnected('User initiated disconnection'));
  }

  readonly isCoinbaseWallet = true;

  protected readonly updateListener = {
    onAccountsUpdate: (accounts: AddressString[]) => {
      if (areAddressArraysEqual(this.accounts, accounts)) return;
      this.accounts = accounts;
      this.emit('accountsChanged', this.accounts);
    },
    onChainUpdate: (chain: Chain) => {
      if (chain.id === this.chain.id && chain.rpcUrl === this.chain.rpcUrl) return;
      this.chain = chain;
      this.emit('chainChanged', hexStringFromNumber(chain.id));
    },
  };

  private requestSignerSelection(): Promise<SignerType> {
    return fetchSignerType({
      communicator: this.communicator,
      preference: this.preference,
      metadata: this.metadata,
    });
  }

  private initSigner(signerType: SignerType): Signer {
    return createSigner({
      signerType,
      metadata: this.metadata,
      communicator: this.communicator,
      updateListener: this.updateListener,
    });
  }
}
