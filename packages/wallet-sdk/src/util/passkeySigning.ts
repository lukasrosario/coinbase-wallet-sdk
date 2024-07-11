import { generateAuthenticationOptions } from '@simplewebauthn/server';
import { toHex } from 'viem';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { startAuthentication } = require('@simplewebauthn/browser');

export async function signWithPasskey(
  base64Hash: string,
  credentialId: string
): Promise<{ authenticatorData: string; clientDataJSON: string; signature: string }> {
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

  return {
    authenticatorData,
    clientDataJSON: sigResponse.clientDataJSON,
    signature: sigResponse.signature,
  };
}
