import { ec } from 'elliptic';

export type KeyPair = ec.KeyPair;

export interface Fee {
  tokenId: string;
  sourceVaultId: number | string;
  feeLimit: string;
}

export interface Transfer {
  senderVaultId: number | string;
  receiverVaultId: number | string;
  amount: string;
  token: string;
  receiverPublicKey: string;
  nonce: number;
  expirationTimestamp: number;
  condition?: string;
  feeInfoUser?: Fee;
}

export interface LimitOrder {
  vaultIdSell: number | string;
  vaultIdBuy: number | string;
  amountSell: string;
  amountBuy: string;
  tokenSell: string;
  tokenBuy: string;
  nonce: number;
  expirationTimestamp: number;
  feeInfo?: Fee;
}

export interface Signature {
  r: string;
  s: string;
}
