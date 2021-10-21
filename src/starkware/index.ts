import BN from 'bn.js';
import { generateMnemonic, mnemonicToSeedSync } from 'bip39';
import { ec } from 'elliptic';
import { hdkey } from 'ethereumjs-wallet';

import { LimitOrder, Transfer, Signature } from './types';
import { getAccountPath, getKeyPairFromPath } from './keyDerivation';
import {
  starkEc,
  sign as starkSign,
  verify as starkVerify,
  getTransferMsgHash,
  getTransferMsgHashWithFee,
  getLimitOrderMsgHash,
  getLimitOrderMsgHashWithFee,
} from './signature';

export const PATH = "m/44'/60'/0'/0/0";

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
  `0x${key
    .getPublic()
    .getX()
    .toString('hex')
    .padStart(64, '0')}`;

export const loadPrivateKey = (privateKey: string) =>
  starkEc.keyFromPrivate(privateKey.substring(2), 'hex');

export const loadPublicKey = (publicKey: string) =>
  starkEc.keyFromPublic(publicKey.substring(2), 'hex');

export const hashTransfer = (transfer: Transfer) => {
  const {
    amount,
    nonce,
    senderVaultId,
    token,
    receiverVaultId,
    receiverPublicKey,
    expirationTimestamp,
    condition,
    fee,
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

  if (fee)
    return getTransferMsgHashWithFee(
      ...args,
      fee.token,
      fee.vaultId,
      fee.limit
    );

  return getTransferMsgHash(...args);
};

export const hashLimitOrder = (limitOrder: LimitOrder) => {
  const {
    vaultIdSell,
    vaultIdBuy,
    amountSell,
    amountBuy,
    tokenSell,
    tokenBuy,
    nonce,
    expirationTimestamp,
    fee,
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

  if (fee)
    return getLimitOrderMsgHashWithFee(
      ...args,
      fee.token,
      fee.vaultId,
      fee.limit
    );

  return getLimitOrderMsgHash(...args);
};

export const sign = (privateKey: string, message: string) => {
  const key = loadPrivateKey(privateKey);
  const { r, s } = starkSign(key, message);

  return {
    r: `0x${r.toString(16)}`,
    s: `0x${s.toString(16)}`,
  };
};

export const verify = (
  publicKey: string,
  message: string,
  signature: Signature
) => {
  const key = loadPublicKey(publicKey);
  const sig = {
    r: new BN(signature.r.substring(2), 16),
    s: new BN(signature.s.substring(2), 16),
  };

  return starkVerify(key, message, sig);
};

export const signTransfer = (privateKey: string, transfer: Transfer) => {
  const message = hashTransfer(transfer);

  return sign(privateKey, message);
};

export const verifyTransfer = (
  publicKey: string,
  transfer: Transfer,
  signature: Signature
) => {
  const message = hashTransfer(transfer);

  return verify(publicKey, message, signature);
};

export const signLimitOrder = (privateKey: string, limitOrder: LimitOrder) => {
  const message = hashLimitOrder(limitOrder);

  return sign(privateKey, message);
};

export const verifyLimitOrder = (
  publicKey: string,
  limitOrder: LimitOrder,
  signature: Signature
) => {
  const message = hashLimitOrder(limitOrder);

  return verify(publicKey, message, signature);
};
