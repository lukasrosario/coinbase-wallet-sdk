const mapping = {
  handshake: ['eth_requestAccounts'],
  sign: [
    'eth_ecRecover',
    'personal_sign',
    'personal_ecRecover',
    'eth_signTransaction',
    'eth_sendTransaction',
    'eth_signTypedData_v1',
    'eth_signTypedData_v3',
    'eth_signTypedData_v4',
    'eth_signTypedData',
    'wallet_addEthereumChain',
    'wallet_switchEthereumChain',
    'wallet_watchAsset',
    'wallet_getCapabilities',
    'wallet_showCallsStatus',
    'wallet_grantPermissions',
  ],
  state: [
    // internal state
    'eth_chainId',
    'eth_accounts',
    'eth_coinbase',
    'net_version',
  ],
  deprecated: ['eth_sign', 'eth_signTypedData_v2'],
  unsupported: ['eth_subscribe', 'eth_unsubscribe'],
  fetch: [],
  signOrFetch: ['wallet_sendCalls'],
} as const;

export type MethodCategory = keyof typeof mapping;
export type Method<C extends MethodCategory = MethodCategory> = (typeof mapping)[C][number];

export function determineMethodCategory(method: string): MethodCategory | undefined {
  for (const c in mapping) {
    const category = c as MethodCategory;
    if ((mapping[category] as readonly string[]).includes(method)) {
      return category;
    }
  }
  return undefined;
}

export type SendCallsParams = [
  {
    capabilities?: {
      permissions?: {
        context?: string;
        credentialId?: string;
      };
    };
  },
];
