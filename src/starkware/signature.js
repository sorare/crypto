// @ts-check
/* eslint-disable no-bitwise */
/* //////////////////////////////////////////////////////////////////////////////
// Copyright 2019 StarkWare Industries Ltd.                                    //
//                                                                             //
// Licensed under the Apache License, Version 2.0 (the "License").             //
// You may not use this file except in compliance with the License.            //
// You may obtain a copy of the License at                                     //
//                                                                             //
// https://www.starkware.co/open-source-license/                               //
//                                                                             //
// Unless required by applicable law or agreed to in writing,                  //
// software distributed under the License is distributed on an "AS IS" BASIS,  //
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.    //
// See the License for the specific language governing permissions             //
// and limitations under the License.                                          //
////////////////////////////////////////////////////////////////////////////// */

import * as starknet from 'micro-starknet';
import assert from 'assert';
/**
 * @param {boolean} test
 * @param {string} message
 */
// const assert = (test, message) => {
//   if (!test) {
//     throw new Error(message);
//   }
// };

// Equals 2**251 + 17 * 2**192 + 1.
const prime = starknet.CURVE.p;

// Equals 2**251. This value limits msgHash and the signature parts.
const maxEcdsaVal = BigInt(
  '0x800000000000000000000000000000000000000000000000000000000000000'
);

const twoPow22 = BigInt('0x400000');
const twoPow31 = BigInt('0x80000000');
const twoPow63 = BigInt('0x8000000000000000');

/**
 * Checks that the string str start with '0x'.
 * @param {string} str
 */
function hasHexPrefix(str) {
  return str.substring(0, 2) === '0x';
}

/**
 * Asserts input is equal to or greater then lowerBound and lower then upperBound.
 * Assert message specifies inputName.
 * inputName should be a string.
 * @param {bigint} input
 * @param {bigint} lowerBound
 * @param {bigint} upperBound
 * @param {string} [inputName]
 */
function assertInRange(input, lowerBound, upperBound, inputName = '') {
  const messageSuffix =
    inputName === '' ? 'invalid length' : `invalid ${inputName} length`;
  assert(
    input >= lowerBound && input < upperBound,
    `Message not signable, ${messageSuffix}.`
  );
}

/**
 * @param {bigint} instructionTypeBi
 * @param {bigint} vault0
 * @param {bigint} vault1
 * @param {bigint} amount0
 * @param {bigint} amount1
 * @param {bigint} nonce
 * @param {bigint} expirationTimestamp
 * @param {string} token0
 * @param {string} token1OrPubKey
 * @param {string | null} [condition]
 * @returns
 */
function hashMsg(
  instructionTypeBi,
  vault0,
  vault1,
  amount0,
  amount1,
  nonce,
  expirationTimestamp,
  token0,
  token1OrPubKey,
  condition = null
) {
  let packedMessage = instructionTypeBi;
  packedMessage = (packedMessage << BigInt(31)) + vault0;
  packedMessage = (packedMessage << BigInt(31)) + vault1;
  packedMessage = (packedMessage << BigInt(63)) + amount0;
  packedMessage = (packedMessage << BigInt(63)) + amount1;
  packedMessage = (packedMessage << BigInt(31)) + nonce;
  packedMessage = (packedMessage << BigInt(22)) + expirationTimestamp;
  let msgHash = null;
  if (condition === null) {
    msgHash = starknet.pedersen(
      starknet.pedersen(token0, token1OrPubKey),
      packedMessage.toString(16)
    );
  } else {
    msgHash = starknet.pedersen(
      starknet.pedersen(starknet.pedersen(token0, token1OrPubKey), condition),
      packedMessage.toString(16)
    );
  }

  assertInRange(BigInt(msgHash), BigInt(0), maxEcdsaVal, 'msgHash');
  return msgHash;
}

/**
 *
 * @param {bigint} instructionType
 * @param {bigint} senderVaultId
 * @param {bigint} receiverVaultId
 * @param {bigint} amount
 * @param {bigint} nonce
 * @param {bigint} expirationTimestamp
 * @param {string} transferToken - non hex prefixed
 * @param {string} receiverPublicKey - non hex prefixed
 * @param {string} feeToken - non hex prefixed
 * @param {bigint} feeVaultId
 * @param {bigint} feeLimit
 * @param {string|null} condition
 * @returns
 */
function hashTransferMsgWithFee(
  instructionType,
  senderVaultId,
  receiverVaultId,
  amount,
  nonce,
  expirationTimestamp,
  transferToken,
  receiverPublicKey,
  feeToken,
  feeVaultId,
  feeLimit,
  condition = null
) {
  let packedMessage1 = senderVaultId;
  packedMessage1 = (packedMessage1 << BigInt(64)) + receiverVaultId;
  packedMessage1 = (packedMessage1 << BigInt(64)) + feeVaultId;
  packedMessage1 = (packedMessage1 << BigInt(32)) + nonce;
  let packedMessage2 = instructionType;
  packedMessage2 = (packedMessage2 << BigInt(64)) + amount;
  packedMessage2 = (packedMessage2 << BigInt(64)) + feeLimit;
  packedMessage2 = (packedMessage2 << BigInt(32)) + expirationTimestamp;
  packedMessage2 = (packedMessage2 << BigInt(81)) + BigInt(0);

  let msgHash = null;
  const tmpHash = starknet.pedersen(
    starknet.pedersen(transferToken, feeToken),
    receiverPublicKey
  );

  if (condition === null) {
    msgHash = starknet.pedersen(
      starknet.pedersen(tmpHash, packedMessage1.toString(16)),
      packedMessage2.toString(16)
    );
  } else {
    msgHash = starknet.pedersen(
      starknet.pedersen(
        starknet.pedersen(tmpHash, condition),
        packedMessage1.toString(16)
      ),
      packedMessage2.toString(16)
    );
  }

  assertInRange(BigInt(msgHash), BigInt(0), maxEcdsaVal, 'msgHash');
  return msgHash;
}

/**
 *
 * @param {bigint} instructionType
 * @param {bigint} vaultSell
 * @param {bigint} vaultBuy
 * @param {bigint} amountSell
 * @param {bigint} amountBuy
 * @param {bigint} nonce
 * @param {bigint} expirationTimestamp
 * @param {string} tokenSell - hex without prefix
 * @param {string} tokenBuy - hex without prefix
 * @param {string} feeToken - hex without prefix
 * @param {bigint} feeVaultId
 * @param {bigint} feeLimit
 * @returns
 */
function hashLimitOrderMsgWithFee(
  instructionType,
  vaultSell,
  vaultBuy,
  amountSell,
  amountBuy,
  nonce,
  expirationTimestamp,
  tokenSell,
  tokenBuy,
  feeToken,
  feeVaultId,
  feeLimit
) {
  let packedMessage1 = amountSell;
  packedMessage1 = (packedMessage1 << BigInt(64)) + amountBuy;
  packedMessage1 = (packedMessage1 << BigInt(64)) + feeLimit;
  packedMessage1 = (packedMessage1 << BigInt(32)) + nonce;
  let packedMessage2 = instructionType;
  packedMessage2 = (packedMessage2 << BigInt(64)) + feeVaultId;
  packedMessage2 = (packedMessage2 << BigInt(64)) + vaultSell;
  packedMessage2 = (packedMessage2 << BigInt(64)) + vaultBuy;
  packedMessage2 = (packedMessage2 << BigInt(32)) + expirationTimestamp;
  packedMessage2 = (packedMessage2 << BigInt(17)) + BigInt(0);

  let msgHash = null;
  const tmpHash = starknet.pedersen(
    starknet.pedersen(tokenSell, tokenBuy),
    feeToken
  );

  msgHash = starknet.pedersen(
    starknet.pedersen(tmpHash, packedMessage1.toString(16)),
    packedMessage2.toString(16)
  );

  assertInRange(BigInt(msgHash), BigInt(0), maxEcdsaVal, 'msgHash');
  return msgHash;
}

/**
 Serializes the order message in the canonical format expected by the verifier.
 party_a sells amountSell coins of tokenSell from vaultSell.
 party_a buys amountBuy coins of tokenBuy into vaultBuy.
 Expected types:
 ---------------
 @param {string|number} vaultSell - uint31 (as int)
 @param {string|number} vaultBuy - uint31 (as int)
 @param {bigint} amountSell - uint63
 @param {bigint} amountBuy - uint63
 @param {string} tokenSell - uint256 field element strictly less than the prime (as hex string with 0x)
 @param {string} tokenBuy - uint256 field element strictly less than the prime (as hex string with 0x)
 @param {number} nonce - uint31 (as int)
 @param {number} expirationTimestamp - uint22 (as int).
*/
export function getLimitOrderMsgHash(
  vaultSell,
  vaultBuy,
  amountSell,
  amountBuy,
  tokenSell,
  tokenBuy,
  nonce,
  expirationTimestamp
) {
  assert(
    hasHexPrefix(tokenSell) && hasHexPrefix(tokenBuy),
    'Hex strings expected to be prefixed with 0x.'
  );
  const vaultSellBi = BigInt(vaultSell);
  const vaultBuyBi = BigInt(vaultBuy);
  const tokenSellBi = BigInt(tokenSell);
  const tokenBuyBi = BigInt(tokenBuy);
  const nonceBi = BigInt(nonce);
  const expirationTimestampBi = BigInt(expirationTimestamp);

  assertInRange(vaultSellBi, BigInt(0), twoPow31);
  assertInRange(vaultBuyBi, BigInt(0), twoPow31);
  assertInRange(amountSell, BigInt(0), twoPow63);
  assertInRange(amountBuy, BigInt(0), twoPow63);
  assertInRange(tokenSellBi, BigInt(0), prime);
  assertInRange(tokenBuyBi, BigInt(0), prime);
  assertInRange(nonceBi, BigInt(0), twoPow31);
  assertInRange(expirationTimestampBi, BigInt(0), twoPow22);

  const instructionType = BigInt(0);
  return hashMsg(
    instructionType,
    vaultSellBi,
    vaultBuyBi,
    amountSell,
    amountBuy,
    nonceBi,
    expirationTimestampBi,
    tokenSell.substring(2),
    tokenBuy.substring(2)
  );
}

/**
 Same as getLimitOrderMsgHash, but also requires the fee info.

 Expected types of fee info params:
 ---------------
 @param {string|number} vaultSell - uint31 (as int)
 @param {string|number} vaultBuy - uint31 (as int)
 @param {bigint} amountSell - uint63
 @param {bigint} amountBuy - uint63
 @param {string} tokenSell - uint256 field element strictly less than the prime (as hex string with 0x)
 @param {string} tokenBuy - uint256 field element strictly less than the prime (as hex string with 0x)
 @param {number} nonce - uint31 (as int)
 @param {number} expirationTimestamp - uint22 (as int).
 @param {string|number} feeVaultId - uint31 (as int)
 @param {bigint} feeLimit - uint63
 @param {string} feeToken - uint256 field element strictly less than the prime (as hex string with 0x)
*/
export function getLimitOrderMsgHashWithFee(
  vaultSell,
  vaultBuy,
  amountSell,
  amountBuy,
  tokenSell,
  tokenBuy,
  nonce,
  expirationTimestamp,
  feeToken,
  feeVaultId,
  feeLimit
) {
  assert(
    hasHexPrefix(tokenSell) && hasHexPrefix(tokenBuy),
    'Hex strings expected to be prefixed with 0x.'
  );
  const vaultSellBi = BigInt(vaultSell);
  const vaultBuyBi = BigInt(vaultBuy);
  const tokenSellBi = BigInt(tokenSell);
  const tokenBuyBi = BigInt(tokenBuy);
  const nonceBi = BigInt(nonce);
  const expirationTimestampBi = BigInt(expirationTimestamp);
  const feeTokenBi = BigInt(feeToken);
  const feeVaultIdBi = BigInt(feeVaultId);

  assertInRange(vaultSellBi, BigInt(0), twoPow31);
  assertInRange(vaultBuyBi, BigInt(0), twoPow31);
  assertInRange(amountSell, BigInt(0), twoPow63);
  assertInRange(amountBuy, BigInt(0), twoPow63);
  assertInRange(tokenSellBi, BigInt(0), prime);
  assertInRange(tokenBuyBi, BigInt(0), prime);
  assertInRange(nonceBi, BigInt(0), twoPow31);
  assertInRange(expirationTimestampBi, BigInt(0), twoPow22);
  assertInRange(feeTokenBi, BigInt(0), prime);
  assertInRange(feeVaultIdBi, BigInt(0), twoPow31);
  assertInRange(feeLimit, BigInt(0), twoPow63);

  const instructionType = BigInt(3);
  return hashLimitOrderMsgWithFee(
    instructionType,
    vaultSellBi,
    vaultBuyBi,
    amountSell,
    amountBuy,
    nonceBi,
    expirationTimestampBi,
    tokenSell.substring(2),
    tokenBuy.substring(2),
    feeToken.substring(2),
    feeVaultIdBi,
    feeLimit
  );
}

/**
 Serializes the transfer message in the canonical format expected by the verifier.
 The sender transfer 'amount' coins of 'token' from vault with id senderVaultId to vault with id
 receiverVaultId. The receiver's public key is receiverPublicKey.
 If a condition is added, it is verified before executing the transfer. The format of the condition
 is defined by the application.
 Expected types:
 ---------------
 @param {bigint} amount - uint63
 @param {number} nonce - uint31 (as int)
 @param {string|number} senderVaultId - uint31 (as int)
 @param {string} token - uint256 field element strictly less than the prime (as hex string with 0x)
 @param {string|number} receiverVaultId - uint31 (as int)
 @param {string} receiverPublicKey - uint256 field element strictly less than the prime (as hex string with 0x)
 @param {number} expirationTimestamp - uint22 (as int).
 @param {string|null} [condition] - uint256 field element strictly less than the prime (as hex string with 0x)
*/
export function getTransferMsgHash(
  amount,
  nonce,
  senderVaultId,
  token,
  receiverVaultId,
  receiverPublicKey,
  expirationTimestamp,
  condition
) {
  assert(
    hasHexPrefix(token) &&
      hasHexPrefix(receiverPublicKey) &&
      (!condition || hasHexPrefix(condition)),
    'Hex strings expected to be prefixed with 0x.'
  );
  const nonceBi = BigInt(nonce);
  const senderVaultIdBi = BigInt(senderVaultId);
  const tokenBi = BigInt(token);
  const receiverVaultIdBi = BigInt(receiverVaultId);
  const receiverPublicKeyBi = BigInt(receiverPublicKey);
  const expirationTimestampBi = BigInt(expirationTimestamp);

  assertInRange(amount, BigInt(0), twoPow63);
  assertInRange(nonceBi, BigInt(0), twoPow31);
  assertInRange(senderVaultIdBi, BigInt(0), twoPow31);
  assertInRange(tokenBi, BigInt(0), prime);
  assertInRange(receiverVaultIdBi, BigInt(0), twoPow31);
  assertInRange(receiverPublicKeyBi, BigInt(0), prime);
  assertInRange(expirationTimestampBi, BigInt(0), twoPow22);
  let instructionType = BigInt(1);
  if (condition) {
    assertInRange(BigInt(condition), BigInt(0), prime, 'condition');
    instructionType = BigInt(2);
  }
  return hashMsg(
    instructionType,
    senderVaultIdBi,
    receiverVaultIdBi,
    amount,
    BigInt(0),
    nonceBi,
    expirationTimestampBi,
    token.substring(2),
    receiverPublicKey.substring(2),
    condition
  );
}

/**
 Same as getTransferMsgHash, but also requires the fee info.

 Expected types of fee info params:
 ---------------
 @param {bigint} amount - uint63
 @param {number} nonce - uint31 (as int)
 @param {string|number} senderVaultId - uint31 (as int)
 @param {string} token - uint256 field element strictly less than the prime (as hex string with 0x)
 @param {string|number} receiverVaultId - uint31 (as int)
 @param {string} receiverStarkKey - uint256 field element strictly less than the prime (as hex string with 0x)
 @param {number} expirationTimestamp - uint22 (as int).
 @param {string|null|undefined} condition - uint256 field element strictly less than the prime (as hex string with 0x)
 @param {string} feeToken - uint256 field element strictly less than the prime (as hex string with 0x)
 @param {number|string} feeVaultId - uint31 (as int)
 @param {bigint} feeLimit - uint63
*/
export function getTransferMsgHashWithFee(
  amount,
  nonce,
  senderVaultId,
  token,
  receiverVaultId,
  receiverStarkKey,
  expirationTimestamp,
  condition,
  feeToken,
  feeVaultId,
  feeLimit
) {
  assert(
    hasHexPrefix(feeToken) &&
      hasHexPrefix(token) &&
      hasHexPrefix(receiverStarkKey) &&
      (!condition || hasHexPrefix(condition)),
    'Hex strings expected to be prefixed with 0x.'
  );
  const nonceBi = BigInt(nonce);
  const senderVaultIdBi = BigInt(senderVaultId);
  const tokenBi = BigInt(token);
  const receiverVaultIdBi = BigInt(receiverVaultId);
  const receiverStarkKeyBi = BigInt(receiverStarkKey);
  const expirationTimestampBi = BigInt(expirationTimestamp);
  const feeTokenBi = BigInt(feeToken);
  const feeVaultIdBi = BigInt(feeVaultId);

  assertInRange(amount, BigInt(0), twoPow63);
  assertInRange(nonceBi, BigInt(0), twoPow31);
  assertInRange(senderVaultIdBi, BigInt(0), twoPow31);
  assertInRange(tokenBi, BigInt(0), prime);
  assertInRange(receiverVaultIdBi, BigInt(0), twoPow31);
  assertInRange(receiverStarkKeyBi, BigInt(0), prime);
  assertInRange(expirationTimestampBi, BigInt(0), twoPow22);
  assertInRange(feeTokenBi, BigInt(0), prime);
  assertInRange(feeVaultIdBi, BigInt(0), twoPow31);
  assertInRange(feeLimit, BigInt(0), twoPow63);

  let instructionType = BigInt(4);
  if (condition) {
    assertInRange(BigInt(condition), BigInt(0), prime, 'condition');
    instructionType = BigInt(5);
  }
  return hashTransferMsgWithFee(
    instructionType,
    senderVaultIdBi,
    receiverVaultIdBi,
    amount,
    nonceBi,
    expirationTimestampBi,
    token.substring(2),
    receiverStarkKey.substring(2),
    feeToken.substring(2),
    feeVaultIdBi,
    feeLimit,
    condition
  );
}
