import EventEmitter from 'eventemitter3';
import { numberToHex } from 'viem';

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
    handshake: async (_: RequestArguments): Promise<AddressString[]> => {
      if (this.connected) {
        this.emit('connect', { chainId: hexStringFromNumber(this.chain.id) });
        return this.accounts;
      }

      const signerType = await this.requestSignerSelection();
      const signer = this.initSigner(signerType);
      const accounts = await signer.handshake();

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
        if (
          !params.capabilities?.permissions?.context ||
          !params.capabilities?.permissions?.credentialId
        ) {
          throw standardErrors.rpc.invalidParams('Missing permissions');
        }
        const hasPermissionsContext = !!params.capabilities?.permissions?.context;
        if (hasPermissionsContext) {
          const fillUserOp = await fetchSessionKeyRPCRequest({
            ...request,
            method: 'wallet_fillUserOp',
          });
          if (!fillUserOp.userOp || !fillUserOp.hash || !fillUserOp.base64Hash) {
            throw standardErrors.rpc.internal('Failed to fill user op');
          }
          const signature = await signWithPasskey(
            fillUserOp.base64Hash,
            params.capabilities.permissions.credentialId
          );
          const sendUserOpWithSignature = await fetchSessionKeyRPCRequest({
            method: 'wallet_sendUserOpWithSignature',
            params: {
              chainId: numberToHex(this.chain.id),
              userOp: fillUserOp.userOp,
              signature,
              permissionsContext: params.capabilities.permissions.context,
            },
          });
          return sendUserOpWithSignature.callsId;
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
