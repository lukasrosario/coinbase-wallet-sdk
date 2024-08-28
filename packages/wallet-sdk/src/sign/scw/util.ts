import { RequestArguments } from ':core/provider/interface';

export function isPresigned(request: RequestArguments): boolean {
  if (request.method !== 'wallet_sendCalls') {
    throw new Error('Invalid method for isPresigned()');
  }

  const { params } = request as {
    params: { capabilities: { permissions: { preparedCalls: object } } }[];
  };

  return Boolean(params[0].capabilities.permissions.preparedCalls);
}
