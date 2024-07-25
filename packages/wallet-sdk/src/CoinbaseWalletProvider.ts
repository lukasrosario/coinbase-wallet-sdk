import EventEmitter from 'eventemitter3';
import { Address, checksumAddress, Hex, numberToHex } from 'viem';

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
  fetchPermissionsRPCRequest,
  fetchRPCRequest,
} from './util/provider';
import { Communicator } from ':core/communicator/Communicator';
import { SignerType } from ':core/message';
import { determineMethodCategory, SendCallsParams } from ':core/provider/method';
import { ScopedLocalStorage } from ':util/ScopedLocalStorage';
import { getCombinedPublicKey } from ':util/signing';
import { signWithLocalKey } from ':util/signing';
import { attemptToGetKey, getKeyForAddress, storeKeyForAddress } from ':util/storage';

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
      if (
        request.method === 'wallet_grantPermissions' &&
        (request.params as { permissions: { signer: { type: string } }[] }).permissions[0].signer
          .type === 'wallet'
      ) {
        const { publicKey, privateKey } = await crypto.subtle.generateKey(
          { name: 'ECDSA', namedCurve: 'P-256' },
          false,
          ['sign']
        );
        const combinedPubKey = await getCombinedPublicKey(publicKey);
        const updatedPermissions = [
          {
            ...(request.params as { permissions: { signer: { type: string } }[] }).permissions[0],
            signer: {
              type: 'passkey',
              data: {
                publicKey: combinedPubKey,
              },
            },
          },
        ];
        const response = (await this.signer.request({
          ...request,
          params: {
            permissions: updatedPermissions,
          },
        })) as { context: Hex }[];

        await storeKeyForAddress(
          this.accounts[0] as Address,
          privateKey,
          response[0].context,
          updatedPermissions
        );

        return response[0];
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
        const localKey = await getKeyForAddress(this.accounts[0] as Address);
        if (localKey) {
          const fillUserOp = await fetchPermissionsRPCRequest({
            ...request,
            method: 'wallet_fillUserOp',
            params: [
              {
                ...params,
                capabilities: {
                  ...params.capabilities,
                  permissions: {
                    ...params.capabilities?.permissions,
                    context: localKey.permissionsContext,
                  },
                },
              },
            ],
          });
          if (!fillUserOp.userOp || !fillUserOp.hash || !fillUserOp.base64Hash) {
            throw standardErrors.rpc.internal('Failed to fill user op');
          }
          const signature = await signWithLocalKey(fillUserOp.base64Hash, localKey.key);
          const sendUserOpWithSignature = await fetchPermissionsRPCRequest({
            method: 'wallet_sendUserOpWithSignature',
            params: {
              chainId: numberToHex(this.chain.id),
              userOp: fillUserOp.userOp,
              signature,
              permissionsContext: localKey.permissionsContext,
            },
          });
          return sendUserOpWithSignature.callsId;
        }
        return await this.signer.request(request);
      }
      throw standardErrors.provider.unsupportedMethod();
    },

    state: async (request: RequestArguments) => {
      const getConnectedAccounts = async (): Promise<AddressString[]> => {
        if (this.connected) return this.accounts;
        const localKey = await attemptToGetKey();
        if (localKey) {
          this.emit('connect', { chainId: hexStringFromNumber(this.chain.id) });
          const accounts = [localKey.address];
          this.accounts = accounts;

          const signer = this.initSigner('scw');
          await signer.handshake(accounts);

          this.signer = signer;
          storeSignerType('scw');

          return accounts;
        }
        throw standardErrors.provider.unauthorized(
          "Must call 'eth_requestAccounts' before other methods"
        );
      };
      const getActivePermissions = async () => {
        if (!this.connected) {
          throw standardErrors.provider.unauthorized(
            "Must call 'eth_requestAccounts' before other methods"
          );
        }
        if (!request.params || !Array.isArray(request.params) || request.params.length === 0) {
          throw standardErrors.rpc.invalidParams();
        }
        if (
          !this.accounts.some(
            (address) =>
              checksumAddress(address as Address) ===
              checksumAddress((request.params as Address[])[0])
          )
        ) {
          throw standardErrors.provider.unauthorized('Address not connected');
        }
        const key = await getKeyForAddress(checksumAddress((request.params as Address[])[0]));
        return {
          permissions: key.permissions,
          context: key.permissionsContext,
        };
      };
      switch (request.method) {
        case 'eth_chainId':
          return hexStringFromNumber(this.chain.id);
        case 'net_version':
          return this.chain.id;
        case 'eth_accounts':
          return await getConnectedAccounts();
        case 'eth_coinbase':
          return (await getConnectedAccounts())[0];
        case 'wallet_getActivePermissions':
          return await getActivePermissions();
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
