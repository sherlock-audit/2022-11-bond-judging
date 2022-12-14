xiaoming90

high

# Existing Circuit Breaker Implementation Allow Faster Taker To Extract Payout Tokens From Market

## Summary

The current implementation of the circuit breaker is not optimal. Thus, the market maker will lose an excessive amount of payout tokens if a quoted token suddenly loses a large amount of value, even with a circuit breaker in place.

## Vulnerability Detail

When the amount of the payout tokens purchased by the taker exceeds the `term.maxDebt`, the taker is still allowed to carry on with the transaction, and the market will only be closed after the current transaction is completed.

https://github.com/sherlock-audit/2022-11-bond/blob/main/src/bases/BondBaseSDA.sol#L427

```solidity
File: BondBaseSDA.sol
426:         // Circuit breaker. If max debt is breached, the market is closed
427:         if (term.maxDebt < market.totalDebt) {
428:             _close(id_);
429:         } else {
430:             // If market will continue, the control variable is tuned to to expend remaining capacity over remaining market duration
431:             _tune(id_, currentTime, price);
432:         }
```

Assume that the state of the SDAM at T0 is as follows:

-  `term.maxDebt` is 110 (debt buffer = 10%)
-  `maxPayout` is 100
- `market.totalDebt` is 99

Assume that the quoted token suddenly loses a large amount of value (e.g. stablecoin depeg causing the quote token to drop to almost zero). Bob decided to purchase as many payout tokens as possible before reaching the `maxPayout` limit to maximize the value he could extract from the market. Assume that Bob is able to purchase 50 bond tokens at T1 before reaching the `maxPayout` limit. As such, the state of the SDAM at T1 will be as follows:

- `term.maxDebt` = 110
- `maxPayout` = 100
- `market.totalDebt` = 99 + 50 = 149

In the above scenario, Bob's purchase has already breached the `term.maxDebt` limit. However, he could still purchase the 50 bond tokens in the current transaction.

## Impact

In the event that the price of the quote token falls to almost zero (e.g. 0.0001 dollars), then the fastest taker will be able to extract as many payout tokens as possible before reaching the `maxPayout` limit from the market. The extracted payout tokens are essentially free for the fastest taker. Taker gain is maker loss.

Additionally, in the event that a quoted token suddenly loses a large amount of value, the amount of payout tokens lost by the market marker is capped at the `maxPayout` limit instead of capping the loss at the `term.maxDebt` limit. This resulted in the market makers losing more payout tokens than expected, and their payout tokens being sold to the takers at a very low price (e.g. 0.0001 dollars).

The market makers will suffer more loss if the `maxPayout` limit of their markets is higher.

## Code Snippet

https://github.com/sherlock-audit/2022-11-bond/blob/main/src/bases/BondBaseSDA.sol#L427

## Tool used

Manual Review

## Recommendation

Considering only allowing takers to purchase bond tokens up to the `term.maxDebt` limit.

For instance, based on the earlier scenario, only allow Bob to purchase up to 11 bond tokens (term.maxDebt[110] - market.totalDebt[99]) instead of allowing him to purchase 50 bond tokens. 

If Bob attempts to purchase 50 bond tokens, the market can proceed to purchase the 11 bond tokens for Bob, and the remaining quote tokens can be refunded back to Bob. After that, since the `term.maxDebt (110) == market.totalDebt (110)`, the market can trigger the circuit breaker to close the market to protect the market from potential extreme market conditions. 

This ensures that bond tokens beyond the `term.maxDebt` limit would not be sold to the taker during extreme market conditions.