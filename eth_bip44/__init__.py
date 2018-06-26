# -*- encoding:utf8 -*-
"""
    author: quanbin_zhu
    time  : 2018/4/17 15:26
"""

from web3 import Web3
from eth_utils import to_checksum_address

from eth_bip44.utils import bytes_to_str, hex_str_to_bytes
from eth_bip44.ethbip44 import HDPrivateKey, HDPublicKey, HDKey, PublicKey, PrivateKey
from eth_keyfile import create_keyfile_json, decode_keyfile_json


class EtherError(Exception):
    def __init__(self, msg):
        self.msg = msg
        super(EtherError, self).__init__(msg)

    @property
    def message(self):
        """
        :return:  dict
         eg: {
            "err" : " .... ", # 错误信息
            "except": " .... ",# 报的异常错误信息，  code=5000 时产生该字段
            "code": 4000 -> 接口调用出错；
                    4001 -> 用户错误信息， 例如密码错误
         }          5000 -> 接口服务错误；
        """
        return self.msg

class EtherCommon(object):

    @classmethod
    def generate_eth_mnemonic(cls, passphrase=""):
        """
        TODO 生成以太坊助记词 （24 个 单词组成）及钱包地址
        :param passphrase:  助记词解析口令， 可以为空；
        :return:
        """
        hdpkey, mnemonic_code = HDPrivateKey.master_key_from_entropy(passphrase=passphrase, strength=256)
        hdp_root_keys = HDKey.from_path(hdpkey, "m/44'/60'/0'")
        acct_pri_key = hdp_root_keys[-1]
        keys = HDKey.from_path(acct_pri_key, '{change}/{index}'.format(change=0, index=0))
        private_key = keys[-1]
        return EtherCommon(_mnemonic=mnemonic_code, _pri=private_key._key, _pub=private_key.public_key)

    @classmethod
    def decode_keystore_from_json(cls, keystore, password):
        """
        TODO 解码Keystore Json格式数据
        :param keystore:   keystore 文件 json 数据， 类型为 dict
        :param password:   交易密码， 对keystore进行解密（对称加密算法）
        :return:
        """
        if not isinstance(keystore, dict):
            raise EtherError({"err" :u"Keystore Json 格式错误！", "code": 4000})

        try:
            hex_pri = decode_keyfile_json(keystore, bytes(password, encoding='utf8'))
            pri_key = PrivateKey.from_bytes(hex_pri)
            return EtherCommon(_pri=pri_key, _pub=pri_key.public_key)

        except Exception as e:
            if str(e) == "MAC mismatch":
                raise EtherError({"err" : u"交易密码错误！", "code": 4001})
            else:
                raise EtherError({"err" : u"keystore解码异常！","exception":  str(e), "code" : 5000})

    @classmethod
    def decode_private_key_from_str(cls, private_key):
        """
         TODO Decodes a Base58Check encoded private-key.
        :param private_key (str): A Base58Check encoded private key.
        :return:
        """
        hex_pri = hex_str_to_bytes(private_key)
        pri_key = PrivateKey.from_bytes(hex_pri)
        return EtherCommon(_pri=pri_key, _pub=pri_key.public_key)

    def __init__(self, _mnemonic = None, _pri = None, _pub = None):
        self._private_key   = _pri
        self._public_key    = _pub
        self._mnemonic      = _mnemonic

    @property
    def mnemonic_codes(self):
        return self._mnemonic

    def keystore(self, password):
        """
        TODO 对私钥进行对称加密 生成 keystore json 格式数据
        :param password:  交易密码
        :return:
        """
        if self._private_key and isinstance(self._private_key, PrivateKey):
            return  create_keyfile_json(bytes(self._private_key), bytes(password, encoding='utf8'))
        else:
            raise EtherError({"err": u"无效的私钥！", "code": 4000})

    @property
    def private_key(self):
        if self._private_key and isinstance(self._private_key, PrivateKey):
            return self._private_key.to_hex()
        else:
            raise EtherError({"err": u"无效的私钥！", "code": 4000})

    @property
    def address(self):
        if self._public_key and isinstance(self._public_key, (HDPublicKey, PublicKey)):
            return self._public_key.address()
        else:
            raise EtherError({"err": u"无效的公钥！", "code": 4000})

    @property
    def public_key(self):
        if self._public_key and isinstance(self._public_key, (HDPublicKey, PublicKey)):
            return bytes_to_str(self._public_key.compressed_bytes)
        else:
            raise EtherError({"err": u"无效的公钥！", "code": 4000})

    def web3py_transaction(self, w3, to, value, nonce=None, chain_id=None, gas_price=None):
        """
        TODO  私链交易转账操作
        调用之前enable该交易特色 web3.eth.enable_unaudited_features()
        :param w3:          Web3 实例 ; eg: w3 = Web3(HTTPProvider('http://localhost:8545'))
        :param to:          交易目的地址
        :param value:       交易数目
        :param chain_id:    私链对应的 id , ETH = 1
        :param gas_price:   GAS 的价格
        :return:   返回交易哈希地址
        """
        if not isinstance(w3, Web3):
            raise EtherError( {"err":u"无效的Web3实例！", "code": 4000})

        # 验证地址
        to_address = to
        try:
            to_address = to_checksum_address(to_address)
        except Exception:
            raise EtherError( {"err":u"无效的转账地址！", "code": 4001})

        try:
            _gasPrice   = gas_price if gas_price else w3.eth.gasPrice
            _chainid    = chain_id  if chain_id  else int(w3.net.chainId)
            _nonce      = nonce     if nonce     else w3.eth.getTransactionCount(to_checksum_address(self.address))
            _gas        = w3.eth.estimateGas({'to': to_address, 'from': to_checksum_address(self.address), 'value': value})
            # 交易参数
            tx_params = {
                'to'        : to_address,
                'value'     : value,
                'gas'       : _gas,
                'gasPrice'  : _gasPrice,
                'nonce'     : _nonce,
                'chainId'   : _chainid
            }
            # 对交易进去签名
            signed  = w3.eth.account.signTransaction(tx_params, self.private_key)
            # When you run sendRawTransaction, you get back the hash of the transaction
            tx_hash = w3.eth.sendRawTransaction(signed.rawTransaction)
            # 本次交易的哈希地址
            return  bytes_to_str(tx_hash)

        except Exception as e:
            if e.args and isinstance(e.args[0], dict):
                code = e.args[0].get("code", None)
                msg  = e.args[0].get("message", None)
                if code == -32000 and isinstance(msg, str) and msg.startswith("known transaction:"):
                    raise EtherError({"err": u"交易过于频繁， 请稍后！", "code": 4001})

            raise EtherError({"err": u"交易异常！", "exception": str(e), "code": 5000})

    def web3py_contract_deploy(self, w3, nonce, abi, bytecode, args):
        """
        TODO 远程部署智能合约
        :param w3:   Web3 实例
        :param abi:   智能合约编译的 abi
        :param bytecode: 智能合约编译bin code
        :return: tx_hash
        """
        from web3.utils.transactions import (
            fill_transaction_defaults,
        )
        if not isinstance(w3, Web3):
            raise EtherError({ "err": u"无效的Web3实例！", "code": 4000})

        contract = w3.eth.contract(abi = abi, bytecode = bytecode)
        deploy_contract = contract.constructor(args)
        gas = deploy_contract.estimateGas()
        deploy_transaction = fill_transaction_defaults(w3, {
            "from": to_checksum_address(self.address),
            "to": "0x",
            "nonce": nonce,
            "gas": gas,
            "gasPrice": w3.eth.gasPrice,
            "chainId": int(w3.net.chainId),
            "data" : deploy_contract.data_in_transaction
        })

        signed_txn = w3.eth.account.signTransaction(deploy_transaction, self.private_key)
        tx_hash = w3.eth.sendRawTransaction(signed_txn.rawTransaction)
        return bytes_to_str(tx_hash)

    def web3py_contract_transaction(self, w3, contract, to, value, nonce=None, chain_id=None, gas_price=None):
        """
        TODO 发行的智能合约交易操作
        调用之前enable该交易特色 web3.eth.enable_unaudited_features()
        :param w3:          Web3 实例 ; eg: w3 = Web3(HTTPProvider('http://localhost:8545'))
        :param contract:    智能合约实例 ; eg: contract = web3.eth.contract(address=to_checksum_address(contract_address), abi=abi)
        :param to:          交易目的地址
        :param value:       交易数目
        :param chain_id:    私链对应的 id , ETH = 1
        :param gas_price:   GAS 的价格
        :return:  返回交易哈希地址
        """
        if not isinstance(w3, Web3):
            raise EtherError({ "err": u"无效的Web3实例！", "code": 4000})

        if getattr(type(contract), '__name__') is not "Contract":
            raise EtherError({ "err": u"无效的Contract实例！", "code": 4000})

        # 验证地址
        to_address = to
        try:
            to_address = to_checksum_address(to_address)
        except Exception:
            raise EtherError({"err": u"无效的转账地址！", "code": 4001})

        try:
            _gasPrice   = gas_price if gas_price else w3.eth.gasPrice
            _chainid    = chain_id if chain_id  else int(w3.net.chainId)
            _nonce      = nonce if nonce else w3.eth.getTransactionCount(to_checksum_address(self.address))
            tx_transfer = contract.functions.transfer(to_address, value)
            _gas        = tx_transfer.estimateGas({"from": to_checksum_address(self.address)})
            contract_tx = tx_transfer.buildTransaction({
                'chainId'   : _chainid,
                'gas'       : _gas,
                'gasPrice'  : _gasPrice,
                'nonce'     : _nonce })

            signed_txn  = w3.eth.account.signTransaction(contract_tx, self.private_key)
            tx_hash     = w3.eth.sendRawTransaction(signed_txn.rawTransaction)
            return bytes_to_str(tx_hash)

        except Exception as e:
            if e.args and isinstance(e.args[0], dict):
                code = e.args[0].get("code", None)
                msg  = e.args[0].get("message", None)
                if code == -32000 and isinstance(msg, str) and msg.startswith("known transaction:"):
                    raise EtherError({"err": u"交易过于频繁， 请稍后！", "code": 4001})
            raise EtherError({"err": u"交易异常！", "exception": str(e), "code": 5000})