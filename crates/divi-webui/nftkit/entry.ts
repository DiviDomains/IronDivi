import { NftKit, createNftApi, signIn, royaltyDue, orgRoyaltyDue } from './packages/nft-kit/src/index.ts';
import { SpentTracker, checkPasted } from './packages/wallet/src/index.ts';
import { TESTNET, SIGHASH_ALL, SINGLE_ACP, txHex, isValidAddress } from './packages/divi-assets/src/index.ts';
(window as any).IronDiviNftKit = { NftKit, createNftApi, signIn, royaltyDue, orgRoyaltyDue, SpentTracker, checkPasted, TESTNET, SIGHASH_ALL, SINGLE_ACP, txHex, isValidAddress };
