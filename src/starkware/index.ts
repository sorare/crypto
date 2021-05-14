import BN from 'bn.js';
import { generateMnemonic, mnemonicToSeedSync } from 'bip39';
import { hdkey } from 'ethereumjs-wallet';

import { LimitOrder, Transfer, Signature } from './types';
import { getAccountPath, getKeyPairFromPath } from './keyDerivation';
import {
  starkEc,
  sign as starkSign,
  verify as starkVerify,
  getTransferMsgHash,
  getLimitOrderMsgHash
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

export const loadPrivateKey = (privateKey: string) =>
  starkEc.keyFromPrivate(privateKey.substring(2), 'hex');

export const loadPublicKey = (publicKey: string) =>
  starkEc.keyFromPublic(publicKey.substring(2), 'hex');

export const hashTransfer = (transfer: Transfer) =>
  getTransferMsgHash(
    transfer.amount,
    transfer.nonce,
    transfer.senderVaultId,
    transfer.token,
    transfer.receiverVaultId,
    transfer.receiverPublicKey,
    transfer.expirationTimestamp,
    transfer.condition
  );

export const hashLimitOrder = (limitOrder: LimitOrder) =>
  getLimitOrderMsgHash(
    limitOrder.vaultIdSell,
    limitOrder.vaultIdBuy,
    limitOrder.amountSell,
    limitOrder.amountBuy,
    limitOrder.tokenSell,
    limitOrder.tokenBuy,
    limitOrder.nonce,
    limitOrder.expirationTimestamp
  );

export const sign = (privateKey: string, message: string) => {
  const key = loadPrivateKey(privateKey);
  const { r, s } = starkSign(key, message);

  return {
    r: `0x${r.toString(16)}`,
    s: `0x${s.toString(16)}`
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
    s: new BN(signature.s.substring(2), 16)
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
