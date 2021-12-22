import { starkEc } from './starkware/signature';

import {
  generateKey,
  signTransfer,
  signLimitOrder,
  verifyTransfer,
  verifyLimitOrder,
} from '.';
import { LimitOrder, Transfer } from './types';

describe('generateKey', () => {
  const mnemonic =
    'range mountain blast problem vibrant void vivid doctor cluster enough melody ' +
    'salt layer language laptop boat major space monkey unit glimpse pause change vibrant';

  const keyPair = generateKey(mnemonic);

  it('generates the expected private key', () => {
    expect(keyPair.getPrivate('hex')).toEqual(
      '0646baa9aefb054dfa205c94b43781baa7b2ec2dfbcee64dbd9d2172283de902'
    );
  });
});

describe('transfer', () => {
  const transfer: Transfer = {
    amount: '2154549703648910716',
    nonce: 1,
    senderVaultId: '34',
    token: '0x3003a65651d3b9fb2eff934a4416db301afd112a8492aaf8d7297fc87dcd9f4',
    receiverVaultId: '21',
    receiverPublicKey:
      '0x5fa3383597691ea9d827a79e1a4f0f7949435ced18ca9619de8ab97e661020',
    expirationTimestamp: 438953,
  };

  const privateKey =
    '0x07cc2767a160d4ea112b436dc6f79024db70b26b11ed7aa2cb6d7eef19ace703';

  describe('without fees', () => {
    const { r, s } = signTransfer(privateKey, transfer);

    it('creates the correct signature', () => {
      expect(r).toEqual(
        '0x4c21b3df630eab38d75b5538e8f635167f4f7107a885d7adf542a7525240323'
      );
      expect(s).toEqual(
        '0x5eacfaa59ed1b63d75241a1dbd9256d2efbe97f9451f2cf2a2af0bad5b5ab69'
      );
    });

    it('can be verified', () => {
      const publicKey = starkEc
        .keyFromPrivate(privateKey.substring(2), 'hex')
        .getPublic(true, 'hex');

      expect(verifyTransfer(`0x${publicKey}`, transfer, { r, s })).toEqual(
        true
      );
    });
  });

  describe('with fees', () => {
    const transferWithFee: Transfer = {
      ...transfer,
      feeInfoUser: {
        sourceVaultId: '46',
        tokenId:
          '0x3003a65651d3b9fb2eff934a4416db301afd112a8492aaf8d7297fc87dcd9f4',
        feeLimit: '10',
      },
    };
    const { r, s } = signTransfer(privateKey, transferWithFee);

    it('creates the correct signature', () => {
      expect(r).toEqual(
        '0x675deb2b8eaa0f424d630fcb0896e42ccae281f5c7c030af82704954ccfafe3'
      );
      expect(s).toEqual(
        '0x62385cdd1b624ba2ac09b3d0edee4ad745b5402f5363217ad776abb5cec65f8'
      );
    });

    it('can be verified', () => {
      const publicKey = starkEc
        .keyFromPrivate(privateKey.substring(2), 'hex')
        .getPublic(true, 'hex');

      expect(
        verifyTransfer(`0x${publicKey}`, transferWithFee, { r, s })
      ).toEqual(true);
    });
  });
});

describe('limitOrder', () => {
  const limitOrder = {
    vaultIdSell: 21,
    vaultIdBuy: 27,
    amountSell: '2154686749748910716',
    amountBuy: '1470242115489520459',
    tokenSell:
      '0x5fa3383597691ea9d827a79e1a4f0f7989c35ced18ca9619de8ab97e661020',
    tokenBuy:
      '0x774961c824a3b0fb3d2965f01471c9c7734bf8dbde659e0c08dca2ef18d56a',
    nonce: 0,
    expirationTimestamp: 438953,
  };

  const privateKey =
    '0x03c1e9550e66958296d11b60f8e8e7a7ad990d07fa65d5f7652c4a6c87d4e3cc';

  describe('without fees', () => {
    const { r, s } = signLimitOrder(privateKey, limitOrder);

    it('creates the correct signature', () => {
      expect(r).toEqual(
        '0x173fd03d8b008ee7432977ac27d1e9d1a1f6c98b1a2f05fa84a21c84c44e882'
      );
      expect(s).toEqual(
        '0x4b6d75385aed025aa222f28a0adc6d58db78ff17e51c3f59e259b131cd5a1cc'
      );
    });

    it('can be verified', () => {
      const publicKey = starkEc
        .keyFromPrivate(privateKey.substring(2), 'hex')
        .getPublic(true, 'hex');

      expect(verifyLimitOrder(`0x${publicKey}`, limitOrder, { r, s })).toEqual(
        true
      );
    });
  });

  describe('with fee', () => {
    const limitOrderWithFee: LimitOrder = {
      ...limitOrder,
      feeInfo: {
        sourceVaultId: '46',
        tokenId:
          '0x3003a65651d3b9fb2eff934a4416db301afd112a8492aaf8d7297fc87dcd9f4',
        feeLimit: '10',
      },
    };

    const { r, s } = signLimitOrder(privateKey, limitOrderWithFee);

    it('creates the correct signature', () => {
      expect(r).toEqual(
        '0x461df4883210443817a91b7792e8ee02b2354b28f415a51a898447558469667'
      );
      expect(s).toEqual(
        '0x1b6d43fba0e3a70dcda6fb595bb7e907f39987703a781508112679332a0454'
      );
    });

    it('can be verified', () => {
      const publicKey = starkEc
        .keyFromPrivate(privateKey.substring(2), 'hex')
        .getPublic(true, 'hex');

      expect(
        verifyLimitOrder(`0x${publicKey}`, limitOrderWithFee, { r, s })
      ).toEqual(true);
    });
  });
});
