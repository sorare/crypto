export interface Fee {
  tokenId: string;
  sourceVaultId: number | string;
  feeLimit: bigint;
}

export interface Transfer {
  senderVaultId: number | string;
  receiverVaultId: number | string;
  amount: bigint;
  token: string;
  receiverPublicKey: string;
  nonce: number;
  expirationTimestamp: number;
  condition?: string | null;
  feeInfoUser?: Fee | null;
}

export interface LimitOrder {
  vaultIdSell: number | string;
  vaultIdBuy: number | string;
  amountSell: bigint;
  amountBuy: bigint;
  tokenSell: string;
  tokenBuy: string;
  nonce: number;
  expirationTimestamp: number;
  feeInfo?: Fee | null;
}

export interface FiatTransfer {
  mangopayWalletId: string;
  operationHash: string;
  currency: string;
  amount: number;
  nonce: number;
}

export type AuthorizationRequest = LimitOrder | Transfer | FiatTransfer;

export interface Signature {
  r: string;
  s: string;
}
