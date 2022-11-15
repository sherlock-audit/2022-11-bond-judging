obront

medium

# Referrers can front run orders to increase referral fee

## Summary

The `setReferrerFee()` function in `BondBaseTeller.sol` has no authorization and can be called by anyone. This can be used by a referrer to front run a user's transaction to temporarily increase the referral fee for the user's transaction.

## Vulnerability Detail

When bonds are purchased from `BondBaseTeller.sol`, the referrer fee is calculated by taking the individual referrer's fee (represented as a fraction of 1e5) and multiplying it by the amount purchased:

```solidity
uint256 toReferrer = amount_.mulDiv(referrerFees[referrer_], FEE_DECIMALS);
```
This fee is set in the `setReferrerFee()` function:
```solidity
function setReferrerFee(uint48 fee_) external override nonReentrant {
    if (fee_ > 5e3) revert Teller_InvalidParams();
    referrerFees[msg.sender] = fee_;
}
```
Because a referrer can set their own fee at any time and there are no validations for a user that the referral fee won't increase above what they expected when they signed their transaction, a referrer can watch the mempool and frontrun user transactions to temporarily increase their fee, earn a higher share of rewards, and lower the fee back.

## Impact

Users may submit a transaction with a clear expectation of the referral fees that will be charged, and end up with a different fee than expected.

## Code Snippet

https://github.com/sherlock-audit/2022-11-bond/blob/main/src/bases/BondBaseTeller.sol#L87-L91

## Tool used

Manual Review

## Recommendation

There are a few ways to avoid this issue, most of which have some complexity. The two options I'd recommend:

1) Along with the referral fee, save the old referral fee and the block at which it was set. Then, in `purchase()`, you can set the fee with `block.number > blockSet ? referralFee : oldReferralFee`.

2) Have users include a "slippage" value that sets the max amount of referral fee they are willing to pay. This can be set to the current referral fee, and will only error if the fee is increased after they signed their transaction.