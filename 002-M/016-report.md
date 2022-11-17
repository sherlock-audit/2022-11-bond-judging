xiaoming90

medium

# Create Fee Discount Feature Is Broken

## Summary

 The create fee discount feature is found to be broken within the protocol. 

## Vulnerability Detail

The create fee discount feature relies on the `createFeeDiscount` state variable to determine the fee to be discounted from the protocol fee. However, it was observed that there is no way to initialize the `createFeeDiscount` state variable. As a result, the `createFeeDiscount` state variable will always be zero.

https://github.com/sherlock-audit/2022-11-bond/blob/main/src/BondFixedExpiryTeller.sol#L118

```solidity
File: BondFixedExpiryTeller.sol
118:         // If fee is greater than the create discount, then calculate the fee and store it
119:         // Otherwise, fee is zero.
120:         if (protocolFee > createFeeDiscount) {
121:             // Calculate fee amount
122:             uint256 feeAmount = amount_.mulDiv(protocolFee - createFeeDiscount, FEE_DECIMALS);
123:             rewards[_protocol][underlying_] += feeAmount;
124: 
125:             // Mint new bond tokens
126:             bondToken.mint(msg.sender, amount_ - feeAmount);
127: 
128:             return (bondToken, amount_ - feeAmount);
129:         } else {
130:             // Mint new bond tokens
131:             bondToken.mint(msg.sender, amount_);
132: 
133:             return (bondToken, amount_);
134:         }
```

https://github.com/sherlock-audit/2022-11-bond/blob/main/src/BondFixedTermTeller.sol#L118

```solidity
File: BondFixedTermTeller.sol
118:         // If fee is greater than the create discount, then calculate the fee and store it
119:         // Otherwise, fee is zero.
120:         if (protocolFee > createFeeDiscount) {
121:             // Calculate fee amount
122:             uint256 feeAmount = amount_.mulDiv(protocolFee - createFeeDiscount, FEE_DECIMALS);
123:             rewards[_protocol][underlying_] += feeAmount;
124: 
125:             // Mint new bond tokens
126:             _mintToken(msg.sender, tokenId, amount_ - feeAmount);
127: 
128:             return (tokenId, amount_ - feeAmount);
129:         } else {
130:             // Mint new bond tokens
131:             _mintToken(msg.sender, tokenId, amount_);
132: 
133:             return (tokenId, amount_);
134:         }
```

## Impact

 The create fee discount feature is broken within the protocol. There is no way for the protocol team to configure a discount for the users of the `BondFixedExpiryTeller.create` and `BondFixedTermTeller.create` functions. As such, the users will not obtain any discount from the protocol when using the create function.

## Code Snippet

https://github.com/sherlock-audit/2022-11-bond/blob/main/src/BondFixedExpiryTeller.sol#L118

https://github.com/sherlock-audit/2022-11-bond/blob/main/src/BondFixedTermTeller.sol#L118

## Tool used

Manual Review

## Recommendation

Implement a setter method for the `createFeeDiscount` state variable and the necessary verification checks.

```solidity
function setCreateFeeDiscount(uint48 createFeeDiscount_) external requiresAuth {
    if (createFeeDiscount_ > protocolFee)  revert Teller_InvalidParams();
    if (createFeeDiscount_ > 5e3) revert Teller_InvalidParams();
    createFeeDiscount = createFeeDiscount_;
}
```