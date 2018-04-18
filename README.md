# 概述
1. 以太坊通用钱包助记词钱包创建; <BR>遵循比特币改进建议[BIP44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)规则， 可参考 [ethfans:【虚拟货币钱包】从 BIP32、BIP39、BIP44 到 Ethereum HD Ｗallet](https://ethfans.org/posts/from-BIP-to-ethereum-HD-wallet);
2. 借鉴 [ethereum-bip44-python](https://github.com/michailbrynard/ethereum-bip44-python) 进行再次封装;
3. eth_bip44.EtherCommon 实现功能;
    - 创建助记词钱包
    - 生成/解析Keystore
    - 通过私钥和KeyStore进行本地链上交易
    - 通过私钥和KeyStore进行本地链上智能合约交易


# 测试代码
```test.py
# -*- encoding:utf8 -*-
"""
    author: quanbin_zhu
    time  : 2018/4/18 10:52
"""

import sys
import json
from web3 import Web3, HTTPProvider
from eth_utils import to_checksum_address
from eth_bip44 import EtherCommon, EtherError

# 用户钱包 keystore
keystore_json   = {
    "address": "8c2c0abbd271c7c8cdde9df789dea7eaef393b58",
    "crypto": {
        "cipher": "aes-128-ctr",
        "cipherparams": {
            "iv": "9ab5faf0d4014db754072ec164cd0368"
        },
        "ciphertext": "8ee65070a18356eb6fa1633c0b2bdaa93d8bd2048f0a7e328b5a10b8084f595c",
        "kdf": "pbkdf2",
        "kdfparams": {
            "c": 1000000,
            "dklen": 32,
            "prf": "hmac-sha256",
            "salt": "79d071fbfae4ec10d02444943beb2df0"
        },
        "mac": "573210dbabe0a08b09be96f083fd4d57427361e857f6a72226792ca6433260d2"
    },
    "id": "0b73708e-23ec-4e77-a7f5-be477edad8f6",
    "version": 3
}
# 钱包密码
password = "password"
http_url = "http://127.0.0.1:8545"

def test_create_wallet_with_mnemonic():
    ec_obj = EtherCommon.generate_eth_mnemonic()
    print (u"==" * 15, u"\n账号带助记词的以太坊钱包：  助记词 => 私钥 认证网址：https://iancoleman.io/bip39/\n", u"==" * 15)
    print (u"助记词\t: ", ec_obj.mnemonic_codes)
    print (u"地址\t: ", ec_obj.address)
    print (u"公钥\t: ", ec_obj.public_key)
    print (u"私钥\t: ", ec_obj.private_key)

    print ("\n", u"==" * 15)
    print (u"生成keystore文件： 私钥 => keystore \n", u"==" * 15)
    keystore = ec_obj.keystore("password")
    print (u"KeyStore\t: ", json.dumps(keystore, indent=4))

    print ("\n", u"==" * 15)
    print (u"解码keystore文件： keystore => 私钥 \n", u"==" * 15)
    ec_obj2 = EtherCommon.decode_keystore_from_json(keystore, "password")
    print (u"地址\t: ", ec_obj2.address)
    print (u"公钥\t: ", ec_obj2.public_key)
    print (u"私钥\t: ", ec_obj2.private_key)

    print ("\n", u"==" * 15)
    print (u"解码私钥： 私钥 => 公钥 + 地址 \n", u"==" * 15)
    ec_obj3 = EtherCommon.decode_private_key_from_str(ec_obj2.private_key)
    print (u"地址\t: ", ec_obj3.address)
    print (u"公钥\t: ", ec_obj3.public_key)
    print (u"私钥\t: ", ec_obj3.private_key)


def test_tx():
    """
    TODO: 私链发起转账交易测试
    """
    # web3 实例
    w3 = Web3(HTTPProvider(http_url))
    w3.eth.enable_unaudited_features()
    # ether common object
    gec_obj = EtherCommon.decode_keystore_from_json(keystore_json, password)
    # 收账人地址
    to = "0x6DBa958da28a0079c83ba5Ba57*****************"
    # 转账金额
    v   = w3.toWei(1.2, "Gwei")
    tx_hash = gec_obj.web3py_transaction(w3, to, v)
    print("Transaction Hash :", tx_hash)
    print(w3.eth.getTransaction(tx_hash))


def test_contract_tx():
    """
    TODO: 私链中发行的智能合约转账交易测试
    """
    # web3 实例
    w3 = Web3(HTTPProvider(http_url))
    w3.eth.enable_unaudited_features()
    # ether common object
    gec_obj = EtherCommon.decode_keystore_from_json(keystore_json, password)
    contract_address = to_checksum_address('0xb9ba8cc04a710dc47488dd9*****************')
    abi = [
        {"constant": True, "inputs": [], "name": "name", "outputs": [{"name": "", "type": "string"}], "payable": False,"stateMutability": "view", "type": "function"},
        {"constant": True, "inputs": [], "name": "decimals", "outputs": [{"name": "", "type": "uint8"}], "payable": False, "stateMutability": "view", "type": "function"},
        {"constant": False, "inputs": [{"name": "_supply", "type": "uint256"}, {"name": "_name", "type": "string"}, {"name": "_symbol", "type": "string"}, {"name": "_decimals", "type": "uint8"}], "name": "TccToken","outputs": [], "payable": False, "stateMutability": "nonpayable","type": "function"},
        {"constant": True, "inputs": [{"name": "", "type": "address"}], "name": "balanceOf","outputs": [{"name": "", "type": "uint256"}], "payable": False, "stateMutability": "view", "type": "function"},
        {"constant": True, "inputs": [], "name": "symbol", "outputs": [{"name": "", "type": "string"}], "payable": False, "stateMutability": "view", "type": "function"},
        {"constant": False, "inputs": [{"name": "_to", "type": "address"}, {"name": "_value", "type": "uint256"}], "name": "transfer", "outputs": [], "payable": False, "stateMutability": "nonpayable", "type": "function"},
        {"anonymous": False, "inputs": [{"indexed": True, "name": "from", "type": "address"},{"indexed": True, "name": "to", "type": "address"},{"indexed": False, "name": "value", "type": "uint256"}], "name": "Transfer","type": "event"}
    ]

    ct = w3.eth.contract(address=contract_address, abi=abi)
    to = "0x6DBa958da28a0079c83ba5Ba57*****************"
    nonce = w3.eth.getTransactionCount(to_checksum_address(gec_obj.address))

    # 连续操作一个账号时， 需手动赋值 nonce， 防止   Error: replacement transaction underpriced
    for i in range(0,5):
        v = w3.toWei(0.13 + 0.1*i, "Gwei")
        tx_hash = gec_obj.web3py_contract_transaction(w3, ct, to, v, nonce+i)
        print("Transaction Hash :", tx_hash)
        print(w3.eth.getTransaction(tx_hash))
        print("=" * 20)
        print()


if __name__ == "__main__":
    try:
        test_create_wallet_with_mnemonic()
    except EtherError as e:
        print("errcode: %d errmsg：%s" % (e.message["code"], e.message["err"]))
        sys.exit(1)
```

# Issue
1. error replacement transaction underpriced：

    因为每个账号每次发起的交易nonce是递增的， 当连续从一个账号上发起交易时，上次的交易可能没有被记录到block上; <BR>
    该Address本次交易的nonce = Address获取的nonce + Address对应的Pending状态的数目<BR>
    参考:
     [Transaction having low gasPrice makes all the other transactions hang on the pending state](https://github.com/ethereum/go-ethereum/issues/16284)


