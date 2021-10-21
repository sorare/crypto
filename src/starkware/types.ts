import { ec } from 'elliptic';

export type KeyPair = ec.KeyPair;

export interface Fee {
  token: string;
  vaultId: string;
  limit: string;
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
  fee?: Fee;
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
  fee?: Fee;
}

export interface Signature {
  r: string;
  s: string;
}
