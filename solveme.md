# Solve Me [194 solves] [50 points]

### Description
```
Aight warm up time. All you gotta do is call the solve function. You can do it!

Goal: Call the solve function!

Author: @bluealder
```

This challenge is very easy, just call a function then its solved

### SolveMe.sol : 
```solidity
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @title SolveMe
 * @author BlueAlder duc.tf
 */
contract SolveMe {
    bool public isSolved = false;

    function solveChallenge() external {
        isSolved = true;
    }
   
}
```

### Solve.py :
```python
from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware

web3 = Web3(HTTPProvider('https://blockchain-solveme-d0503f263b983a0a-eth.2022.ductf.dev/'))
web3.middleware_onion.inject(geth_poa_middleware, layer=0)

address = '0x6E4198C61C75D1B4D1cbcd00707aAC7d76867cF8'
abi = '[{"inputs":[],"name":"isSolved","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"solveChallenge","outputs":[],"stateMutability":"nonpayable","type":"function"}]'
contract_instance = web3.eth.contract(address=address, abi=abi)

wallet = '0xD8079d2A994820C1df68AC8141407dC6D8E0A136'
private_key = '0x19645224aa9d41232d1625e51c58144f99120170d76861184fa60ca64a0d3fa3'

nonce = web3.eth.getTransactionCount(wallet)
gasPrice = web3.toWei('4', 'gwei')
gasLimit = 100000
tx = {
    'nonce': nonce,
    'gas': gasLimit,
    'gasPrice': gasPrice,
    'from': wallet
}
transaction = contract_instance.functions.solveChallenge().buildTransaction(tx)
signed_tx = web3.eth.account.sign_transaction(transaction, private_key)
tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
transaction_hash = web3.toHex(tx_hash)
tx_receipt = web3.eth.wait_for_transaction_receipt(transaction_hash)
print(tx_receipt['status'])
```

### Flag : 

```json
{"flag":"DUCTF{muM_1_did_a_blonkchain!}"}
```