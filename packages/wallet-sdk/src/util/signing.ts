import { generateAuthenticationOptions } from '@simplewebauthn/server';
import { isoBase64URL } from '@simplewebauthn/server/helpers';
import {
  bytesToBigInt,
  bytesToHex,
  concat,
  encodeAbiParameters,
  Hex,
  sha256,
  stringToHex,
  toHex,
} from 'viem';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { startAuthentication } = require('@simplewebauthn/browser');

function getAuthData(): Uint8Array {
  const rpBytes = new Uint8Array(Buffer.from(window.location.hostname, 'utf8'));
  const rpIdHash = sha256(rpBytes, 'bytes');
  const flagsBuf = new Uint8Array([5]);
  const signCountBuf = new Uint8Array([0, 0, 0, 0]);
  return concat([rpIdHash, flagsBuf, signCountBuf]);
}

function getClientDataJSON(hash: string): Uint8Array {
  return isoBase64URL.toBuffer(
    isoBase64URL.fromUTF8String(
      JSON.stringify({
        type: 'webauthn.get',
        challenge: hash,
        origin: window.location.origin,
        crossOrigin: false,
      })
    )
  );
}

export async function getCombinedPublicKey(publicKey: CryptoKey) {
  const exported = await crypto.subtle.exportKey('jwk', publicKey);
  const combined = encodeAbiParameters(
    [
      { name: 'x', type: 'uint256' },
      { name: 'y', type: 'uint256' },
    ],
    [
      bytesToBigInt(isoBase64URL.toBuffer(exported.x as string)),
      bytesToBigInt(isoBase64URL.toBuffer(exported.y as string)),
    ]
  );
  return combined;
}

export async function signWithLocalKey(base64Hash: string, key: CryptoKey): Promise<Hex> {
  const authData = getAuthData();
  const clientDataJSON = getClientDataJSON(base64Hash);
  const clientDataJSONHash = sha256(clientDataJSON, 'bytes');
  const toSign = concat([authData, clientDataJSONHash]);
  const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, toSign);
  const buffer = Buffer.from(signature);
  const base64Signature = isoBase64URL.fromBuffer(buffer);
  const { r, s } = extractRSFromSig(base64Signature);

  const webAuthnSignature = buildWebAuthnSignature({
    authenticatorData: bytesToHex(authData),
    clientDataJSON: isoBase64URL.fromBuffer(clientDataJSON),
    r,
    s,
  });

  return webAuthnSignature;
}

export async function signWithPasskey(base64Hash: string, credentialId: string): Promise<Hex> {
  const options = await generateAuthenticationOptions({
    rpID: window.location.hostname,
    challenge: base64Hash,
    userVerification: 'preferred',
    allowCredentials: [
      {
        id: credentialId,
        transports: ['internal'],
      },
    ],
  });
  options.challenge = base64Hash;

  const { response: sigResponse } = await startAuthentication(options);

  const authenticatorData = toHex(Buffer.from(sigResponse.authenticatorData, 'base64'));

  const { r, s } = extractRSFromSig(sigResponse.signature);
  const webAuthnSignature = buildWebAuthnSignature({
    authenticatorData,
    clientDataJSON: sigResponse.clientDataJSON,
    r,
    s,
  });

  return webAuthnSignature;
}

export function extractRSFromSig(base64Signature: string): {
  r: bigint;
  s: bigint;
} {
  // Create an ECDSA instance with the secp256r1 curve

  // Decode the signature from Base64
  // const signatureDER = Buffer.from(base64Signature, 'base64');
  // const parsedSignature = p256.Signature.fromDER(signatureDER);
  // const bSig = hexToBytes(`0x${parsedSignature.toCompactHex()}`);
  // assert(bSig.length === 64, "signature is not 64 bytes");
  // const bR = bSig.slice(0, 32);
  // const bS = bSig.slice(32);

  const signatureBytes = isoBase64URL.toBuffer(base64Signature);
  const bR = signatureBytes.slice(0, 32);
  const bS = signatureBytes.slice(32);

  // Avoid malleability. Ensure low S (<= N/2 where N is the curve order)
  const r = bytesToBigInt(bR);
  let s = bytesToBigInt(bS);
  const n = BigInt('0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551');
  if (s > n / BigInt(2)) {
    s = n - s;
  }
  return { r, s };
}

type BuildUserOperationParams = {
  authenticatorData: string;
  clientDataJSON: string;
  r: bigint;
  s: bigint;
};

export function buildWebAuthnSignature({
  authenticatorData,
  clientDataJSON,
  r,
  s,
}: BuildUserOperationParams): Hex {
  const jsonClientDataUtf8 = isoBase64URL.toUTF8String(clientDataJSON);
  const challengeIndex = jsonClientDataUtf8.indexOf('"challenge":');
  const typeIndex = jsonClientDataUtf8.indexOf('"type":');

  const webAuthnAuthBytes = encodeAbiParameters(
    [WebAuthnAuthStruct],
    [
      {
        authenticatorData,
        clientDataJSON: stringToHex(jsonClientDataUtf8),
        challengeIndex,
        typeIndex,
        r,
        s,
      },
    ]
  );

  return webAuthnAuthBytes;
}
const WebAuthnAuthStruct = {
  components: [
    {
      name: 'authenticatorData',
      type: 'bytes',
    },
    { name: 'clientDataJSON', type: 'bytes' },
    { name: 'challengeIndex', type: 'uint256' },
    { name: 'typeIndex', type: 'uint256' },
    {
      name: 'r',
      type: 'uint256',
    },
    {
      name: 's',
      type: 'uint256',
    },
  ],
  name: 'WebAuthnAuth',
  type: 'tuple',
};
