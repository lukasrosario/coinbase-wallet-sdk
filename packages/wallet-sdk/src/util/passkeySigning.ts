import { p256 } from '@noble/curves/p256';
import { generateAuthenticationOptions } from '@simplewebauthn/server';
import { isoBase64URL } from '@simplewebauthn/server/helpers';
import { bytesToBigInt, encodeAbiParameters, Hex, hexToBytes, stringToHex, toHex } from 'viem';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { startAuthentication } = require('@simplewebauthn/browser');

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
  const signatureDER = Buffer.from(base64Signature, 'base64');
  const parsedSignature = p256.Signature.fromDER(signatureDER);
  const bSig = hexToBytes(`0x${parsedSignature.toCompactHex()}`);
  // assert(bSig.length === 64, "signature is not 64 bytes");
  const bR = bSig.slice(0, 32);
  const bS = bSig.slice(32);

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
