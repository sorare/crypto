import { generateMnemonic, mnemonicToSeedSync } from 'bip39';
import { ec } from 'elliptic';
import { hdkey } from 'ethereumjs-wallet';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex as toHex } from '@noble/hashes/utils';
import * as starknet from 'micro-starknet';

import { LimitOrder, Transfer, Signature } from './types';
import { getAccountPath, getKeyPairFromPath } from './starkware/keyDerivation';
import {
  starkEc,
  getTransferMsgHash,
  getTransferMsgHashWithFee,
  getLimitOrderMsgHash,
  getLimitOrderMsgHashWithFee,
} from './starkware/signature';

export { LimitOrder, Transfer, Signature } from './types';

const PATH = "m/44'/60'/0'/0/0";

export const generateKey = (mnemonic?: string) => {
  const seed = mnemonicToSeedSync(mnemonic || generateMnemonic());
  const ethereumAddress = hdkey
    .fromMasterSeed(seed)
    .derivePath(PATH)
    .getWallet()
    .getAddressString();

  const path = getAccountPath('starkex', 'sorare', ethereumAddress, 0);
  return getKeyPairFromPath(mnemonic, path);
};

export const exportPrivateKey = (key: ec.KeyPair) =>
  `0x${key.getPrivate('hex').padStart(64, '0')}`;

export const exportPublicKey = (key: ec.KeyPair) =>
  `0x${key.getPublic(true, 'hex')}`;

export const exportPublicKeyX = (key: ec.KeyPair) =>
  `0x${key // force line-break (https://github.com/prettier/prettier/issues/3107)
    .getPublic()
    .getX()
    .toString('hex')
    .padStart(64, '0')}`;

export const loadPrivateKey = (privateKey: string) =>
  starkEc.keyFromPrivate(privateKey.substring(2), 'hex');

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
  ];

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
  ];

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
