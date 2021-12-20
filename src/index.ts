import BN from "bn.js";
import { generateMnemonic, mnemonicToSeedSync } from "bip39";
import { ec } from "elliptic";
import { hdkey } from "ethereumjs-wallet";

import { LimitOrder, Transfer, Signature } from "./types";
import { getAccountPath, getKeyPairFromPath } from "./starkware/keyDerivation";
import {
  starkEc,
  sign as starkSign,
  verify as starkVerify,
  getTransferMsgHash,
  getTransferMsgHashWithFee,
  getLimitOrderMsgHash,
  getLimitOrderMsgHashWithFee,
} from "./starkware/signature";

const PATH = "m/44'/60'/0'/0/0";

export const generateKey = (mnemonic?: string) => {
  const seed = mnemonicToSeedSync(mnemonic || generateMnemonic());
  const ethereumAddress = hdkey
    .fromMasterSeed(seed)
    .derivePath(PATH)
    .getWallet()
    .getAddressString();

  const path = getAccountPath("starkex", "sorare", ethereumAddress, 0);
  return getKeyPairFromPath(mnemonic, path);
};

export const exportPrivateKey = (key: ec.KeyPair): string =>
  `0x${key.getPrivate("hex").padStart(64, "0")}`;

export const exportPublicKey = (key: ec.KeyPair): string =>
  `0x${key.getPublic(true, "hex")}`;

export const exportPublicKeyX = (key: ec.KeyPair): string =>
  `0x${key
    .getPublic()
    .getX()
    .toString("hex")
    .padStart(64, "0")}`;

export const loadPrivateKey = (privateKey: string): ec.KeyPair =>
  starkEc.keyFromPrivate(privateKey.substring(2), "hex");

export const loadPublicKey = (publicKey: string): ec.KeyPair =>
  starkEc.keyFromPublic(publicKey.substring(2), "hex");

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

const sign = (privateKey: string, message: string) => {
  const key = loadPrivateKey(privateKey);
  const { r, s } = starkSign(key, message);

  return {
    r: `0x${r.toString(16)}`,
    s: `0x${s.toString(16)}`,
  };
};

const verify = (publicKey: string, message: string, signature: Signature) => {
  const key = loadPublicKey(publicKey);
  const sig = {
    r: new BN(signature.r.substring(2), 16),
    s: new BN(signature.s.substring(2), 16),
  };

  return starkVerify(key, message, sig);
};

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

  return verify(publicKey, message, signature);
};

export const signLimitOrder = (
  privateKey: string,
  limitOrder: LimitOrder
): Signature => {
  const message = hashLimitOrder(limitOrder);

  return sign(privateKey, message);
};

export const signLimitOrders = (
  privateKey: string,
  limitOrders: [LimitOrder]
): Signature[] => {
  return limitOrders.map((limitOrder) =>
    signLimitOrder(privateKey, limitOrder)
  );
};

export const verifyLimitOrder = (
  publicKey: string,
  limitOrder: LimitOrder,
  signature: Signature
): boolean => {
  const message = hashLimitOrder(limitOrder);

  return verify(publicKey, message, signature);
};
