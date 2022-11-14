Bnke0x0

medium

# Solmate safetransfer and safetransferfrom does not check the code size of the token address, which may lead to funding loss

## Summary

## Vulnerability Detail

## Impact
the safetransfer and safetransferfrom don't check the existence of code at the token address. This is a known issue while using solmate's libraries. Hence this may lead to miscalculation of funds and may lead to loss of funds, because if safetransfer() and safetransferfrom() are called on a token address that doesn't have a contract in it, it will always return success, bypassing the return value check. Due to this protocol will think that funds have been transferred successfully, and records will be accordingly calculated, but in reality, funds were never transferred. So this will lead to miscalculation and possibly loss of funds

## Code Snippet
https://github.com/sherlock-audit/2022-11-bond/blob/main/src/bases/BondBaseCallback.sol#L143

        'token_.safeTransfer(to_, amount_);'

https://github.com/sherlock-audit/2022-11-bond/blob/main/src/bases/BondBaseCallback.sol#L152


           'token_.safeTransferFrom(msg.sender, address(this), amount_);'

https://github.com/sherlock-audit/2022-11-bond/blob/main/src/bases/BondBaseTeller.sol#L108


         'token.safeTransfer(to_, send);'


https://github.com/sherlock-audit/2022-11-bond/blob/main/src/bases/BondBaseTeller.sol#L187


          'quoteToken.safeTransferFrom(msg.sender, address(this), amount_);'



https://github.com/sherlock-audit/2022-11-bond/blob/main/src/bases/BondBaseTeller.sol#L195


            'quoteToken.safeTransfer(callbackAddr, amountLessFee);'


https://github.com/sherlock-audit/2022-11-bond/blob/main/src/bases/BondBaseTeller.sol#L210


            'payoutToken.safeTransferFrom(owner, address(this), payout_);'


https://github.com/sherlock-audit/2022-11-bond/blob/main/src/bases/BondBaseTeller.sol#L214


                'quoteToken.safeTransfer(owner, amountLessFee);'



https://github.com/sherlock-audit/2022-11-bond/blob/main/src/BondFixedExpiryTeller.sol#L89


          'underlying_.safeTransfer(recipient_, payout_);'



https://github.com/sherlock-audit/2022-11-bond/blob/main/src/BondFixedExpiryTeller.sol#L114


           'underlying_.safeTransferFrom(msg.sender, address(this), amount_);'



https://github.com/sherlock-audit/2022-11-bond/blob/main/src/BondFixedExpiryTeller.sol#L152


        'underlying.safeTransfer(msg.sender, amount_);'


https://github.com/sherlock-audit/2022-11-bond/blob/main/src/BondFixedTermTeller.sol#L90


          'payoutToken_.safeTransfer(recipient_, payout_);'



https://github.com/sherlock-audit/2022-11-bond/blob/main/src/BondFixedTermTeller.sol#L114


                'underlying_.safeTransferFrom(msg.sender, address(this), amount_);'


https://github.com/sherlock-audit/2022-11-bond/blob/main/src/BondFixedTermTeller.sol#L151


                'meta.underlying.safeTransfer(msg.sender, amount_);'


https://github.com/sherlock-audit/2022-11-bond/blob/main/src/BondSampleCallback.sol#L42


          'payoutToken_.safeTransfer(msg.sender, outputAmount_);'

## Tool used

Manual Review

## Recommendation
Use openzeppelin's safeERC20 or implement a code existence check
