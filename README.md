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

## `signLimitOrders`

The `signLimitOrders(privateKey, limitOrders)` function is used to sign a list of `LimitOrder` objects with a Sorare private key.

```ts
import { signLimitOrders } from '@sorare/crypto';

const privateKey = /* Your Sorare private key */;
const limitOrders = /* The list of LimitOrder objects you get from GraphQL */;

const signature = signLimitOrders(privateKey, limitOrders);
```

# License

`@sorare/crypto` is [MIT licensed](LICENSE).
