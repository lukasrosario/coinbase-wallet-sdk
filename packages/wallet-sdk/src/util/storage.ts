import { Address, checksumAddress, Hex } from 'viem';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { openDB } = require('idb');

async function getDatabase() {
  return openDB('cbw', 1, {
    upgrade(db: IDBDatabase) {
      if (!db.objectStoreNames.contains('keys')) {
        const keysStore = db.createObjectStore('keys', { keyPath: 'address' });
        keysStore.createIndex('address', 'address', { unique: true });
      }
    },
  });
}

export async function storeKeyForAddress(
  address: Address,
  key: CryptoKey,
  permissionsContext: Hex,
  permissions: unknown[]
) {
  const db = await getDatabase();
  await db.put('keys', { address: checksumAddress(address), key, permissionsContext, permissions });
}

export async function getKeyForAddress(address: Address) {
  const db = await getDatabase();
  const key = await db.get('keys', checksumAddress(address));
  return key;
}

export async function attemptToGetKey() {
  const db = await getDatabase();
  const keys = await db.getAll('keys');
  return keys ? keys[0] : undefined;
}
