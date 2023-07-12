import { generateMnemonic, mnemonicToSeedSync } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/french';
import { HDKey } from '@scure/bip32';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { keccak_256 as keccak } from '@noble/hashes/sha3';
import { bytesToHex as toHex } from '@noble/hashes/utils';
import * as starknet from 'micro-starknet';

import { LimitOrder, Transfer, Signature } from './types';
import {
  getTransferMsgHash,
  getTransferMsgHashWithFee,
  getLimitOrderMsgHash,
  getLimitOrderMsgHashWithFee,
} from './starkware/signature';

export { LimitOrder, Transfer, Signature } from './types';
export { getPublicKey } from 'micro-starknet';

const PATH = "m/44'/60'/0'/0/0";

/**
 * @returns {string} hex encoded 32 byte private string
 */
export const generateKey = (mnemonic?: string) => {
  const seed = mnemonicToSeedSync(mnemonic || generateMnemonic(wordlist));

  // Ethereum wallet public key
  const publicKey = secp256k1
    .getPublicKey(
      toHex(HDKey.fromMasterSeed(seed).derive(PATH)!.privateKey!),
      false
    )
    .slice(1);

  const address = keccak(publicKey).slice(-20);

  const path = starknet.getAccountPath(
    'starkex',
    'sorare',
    `0x${toHex(address)}`,
    0
  );

  const keySeed = toHex(HDKey.fromMasterSeed(seed).derive(path).privateKey!);
  const privateKey = starknet.grindKey(`0x${keySeed}`);
  return privateKey.padStart(64, '0');
};

const hashTransfer = (transfer: Transfer) => {
  const {
    amount,
    nonce,
    senderVaultId,
    token,
    receiverVaultId,
    receiverPublicKey,
    expirationTimestamp,
    condition,
    feeInfoUser,
  } = transfer;

  const args = [
    amount,
    nonce,
    senderVaultId,
    token,
    receiverVaultId,
    receiverPublicKey,
    expirationTimestamp,
    condition,
  ] as const;

  if (feeInfoUser)
    return getTransferMsgHashWithFee(
      ...args,
      feeInfoUser.tokenId,
      feeInfoUser.sourceVaultId,
      feeInfoUser.feeLimit
    );

  return getTransferMsgHash(...args);
};

const hashLimitOrder = (limitOrder: LimitOrder) => {
  const {
    vaultIdSell,
    vaultIdBuy,
    amountSell,
    amountBuy,
    tokenSell,
    tokenBuy,
    nonce,
    expirationTimestamp,
    feeInfo,
  } = limitOrder;

  const args = [
    vaultIdSell,
    vaultIdBuy,
    amountSell,
    amountBuy,
    tokenSell,
    tokenBuy,
    nonce,
    expirationTimestamp,
  ] as const;

  if (feeInfo)
    return getLimitOrderMsgHashWithFee(
      ...args,
      feeInfo.tokenId,
      feeInfo.sourceVaultId,
      feeInfo.feeLimit
    );

  return getLimitOrderMsgHash(...args);
};

const sign = (privateKey: string, message: string): Signature => {
  const { r, s } = starknet.sign(message, privateKey);

  return {
    r: `0x${r.toString(16)}`,
    s: `0x${s.toString(16)}`,
  };
};

const verify = ({ r, s }: Signature, message: string, publicKey: string) => {
  const signature = new starknet.Signature(BigInt(r), BigInt(s));
  return starknet.verify(signature, message, publicKey);
};

const hashMessage = (message: string) => {
  const h = toHex(sha256(message));
  return starknet.pedersen(h.substring(0, 32), h.substring(32)).slice(2);
};

export const signMessage = (privateKey: string, message: string): Signature =>
  sign(privateKey, hashMessage(message));

export const verifyMessage = (
  publicKey: string,
  message: string,
  signature: Signature
) => verify(signature, hashMessage(message), publicKey);

export const signTransfer = (
  privateKey: string,
  transfer: Transfer
): Signature => {
  const message = hashTransfer(transfer);

  return sign(privateKey, message);
};

export const verifyTransfer = (
  publicKey: string,
  transfer: Transfer,
  signature: Signature
): boolean => {
  const message = hashTransfer(transfer);

  return verify(signature, message, publicKey);
};

export const signLimitOrder = (
  privateKey: string,
  limitOrder: LimitOrder
): Signature => {
  const message = hashLimitOrder(limitOrder);

  return sign(privateKey, message);
};

export const verifyLimitOrder = (
  publicKey: string,
  limitOrder: LimitOrder,
  signature: Signature
): boolean => {
  const message = hashLimitOrder(limitOrder);
  return verify(signature, message, publicKey);
};
