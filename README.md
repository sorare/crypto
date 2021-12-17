<!-- logo -->
<p align="center">
  <img src="logo.png">
</p>

<!-- tag line -->
<h4 align='center'>JavaScript Crypto helpers for Sorare</h4>

<!-- primary badges -->
<p align="center">
  <a href="https://www.typescriptlang.org/">
    <img src='https://badges.aleen42.com/src/typescript.svg' />
  </a> 
  <a href="https://www.npmjs.com/package/@sorare/crypto">
    <img src='https://img.shields.io/github/package-json/v/@sorare/crypto?label=npm' />
  </a>
  <a href="https://starkware.co/">
    <img src="https://img.shields.io/badge/powered_by-StarkWare-navy">
  </a>
</p>

`@sorare/crypto` is a JavaScript library providing various crypto functions to be used to sign your Sorare LimitOrder objects in order to make a bid, create or accept an offer. It can be used in both NodeJS and Browser environments.

# Functions

## `signLimitOrder`

The `signLimitOrder(privateKey, limitOrder)` function is used to sign a `LimitOrder` object with a Sorare private key.

```ts
import { signLimitOrder } from '@sorare/crypto';

const privateKey = /* Your Sorare private key */;
const limitOrder = /* The LimitOrder object you get from GraphQL */;

const signature = signLimitOrder(privateKey, limitOrder);
```

# License

`@sorare/crypto` is [MIT licensed](LICENSE).
