# -*- encoding:utf8 -*-
"""
    author: quanbin_zhu
    time  : 2018/4/18 10:52
"""

import json
import time
from web3 import Web3, HTTPProvider
from eth_utils import to_checksum_address
from eth_bip44 import EtherCommon, EtherError

# 用户钱包 keystore
keystore_json   = {"address":"9b4eabea5d69a3c434c40f84f65282f6b4d9b232","crypto":{"cipher":"aes-128-ctr","ciphertext":"0c1a562d3a28682f28a02de89927adbacd99168e9efa48fe3ff0a85df70febac","cipherparams":{"iv":"6cdadf4f3f38af7a4aee1843198a9c00"},"kdf":"scrypt","kdfparams":{"dklen":32,"n":262144,"p":1,"r":8,"salt":"20b525e4dbfac089dd9c5c65fb873a9e530d42f47610647fe31b23f6e348f58e"},"mac":"1651c2597ccedb675f372ad49f0ad30fb5a6c604ee5bda7283e35ed3f9da3ba7"},"id":"6d3f052d-bdf7-411f-bc99-86b7e73fb6a3","version":3}
# 钱包密码
password = "123456"
http_url = "http://192.168.3.193:8541"

class TestBip44(object):
    def __init__(self, ck=keystore_json, cp=password):
        # web3 实例
        self.w3 = Web3(HTTPProvider(http_url))
        self.w3.eth.enable_unaudited_features()
        self.coinbase_keystore = ck
        self.coinbase_password = cp
        self.account1 = EtherCommon.generate_eth_mnemonic()
        self.account2 = EtherCommon.generate_eth_mnemonic()
        # compile with truffle
        with open("BoreyToken.json") as fp:
            data = fp.read()
            self.contract_info = json.loads(data)

    def create_wallet_with_mnemonic(self):
        """
        TODO: 助记词创建测试， keystore解码
        """
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

    def send_tx(self, keystore, password, to, value,):
        """
        TODO: 私链发起转账交易测试
        """
        # ether common object
        gec_obj = EtherCommon.decode_keystore_from_json(keystore, password)
        v = self.w3.toWei(value, "ether")
        tx_hash = gec_obj.web3py_transaction(self.w3, to, v)
        print("Send Ether from: %s, to: %s, value: %s" % (gec_obj.address, to, v))
        _ = self.waiting_for_transaction(tx_hash)

    def deploy_contract_and_tx(self):
        """
        TODO: 使用keystore部署智能合约并进行转账测试
        """
        # 1. 发送ether到新创建的钱包地址
        print(
            """################################################################\n########    send 3 ether from coinbase to account1     #########\n################################################################""")

        self.send_tx(self.coinbase_keystore, self.coinbase_password, self.account1.address, 3)

        # 2. 使用新的钱包地址进行发现只能合约
        print("\n\n\n")
        print(
            """################################################################\n########         deploy contract with account1         #########\n################################################################""")
        print(self.contract_info["source"])
        nonce = self.w3.eth.getTransactionCount(to_checksum_address(self.account1.address))
        tx_hash = self.account1.web3py_contract_deploy(self.w3, nonce, self.contract_info["abi"], self.contract_info["bytecode"], (10 ** 8))
        tx_receipt = self.waiting_for_transaction(tx_hash)
        contract_address = tx_receipt['contractAddress']
        print("Contract Address : %s" % contract_address)

        # 3. 智能合约中token 交易
        print("\n\n\n")
        print(
            """################################################################\n########     send token from account1 to account2      #########\n################################################################""")

        contract = self.w3.eth.contract(address=contract_address, abi=self.contract_info["abi"])
        nonce += 1
        # 连续操作一个账号时， 需手动赋值 nonce， 防止   Error: replacement transaction underpriced
        for i in range(0,5):
            v = 100 * i
            tx_hash = self.account1.web3py_contract_transaction(self.w3, contract, self.account2.address, v, nonce+i)
            print("Transaction Hash :", tx_hash)

        _ = self.waiting_for_transaction(tx_hash)

        # 4. 查询智能合约token的余额
        print("\n\n\n")
        print("[Wallet] %s token: " % self.account1.address, contract.functions.balanceOf(to_checksum_address(self.account1.address)).call())
        print("[Wallet] %s token: " % self.account2.address, contract.functions.balanceOf(to_checksum_address(self.account2.address)).call())

    def waiting_for_transaction(self, tx_hash, msg = "Waiting transaction receipt", secs = 2):
        # tx = "0x%s" % tx_hash if not tx_hash.startswith("0x") else tx_hash
        print("Get transaction receipt: %s" % tx_hash)
        tx_receipt = None
        while not tx_receipt:
            tx_receipt = self.w3.eth.getTransactionReceipt(tx_hash)
            if not tx_receipt:
                print("%s, sleep %s seconds ... " % (msg, secs))
                time.sleep(secs)
        return tx_receipt

if __name__ == "__main__":
    TestBip44().deploy_contract_and_tx()

