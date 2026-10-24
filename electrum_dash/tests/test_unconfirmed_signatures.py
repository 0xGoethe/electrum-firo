import asyncio
import copy
from unittest import mock

from aiorpcx import RPCError

from electrum_firo import bitcoin, ecc
from electrum_firo.address_synchronizer import TX_HEIGHT_UNCONFIRMED
from electrum_firo.simple_config import SimpleConfig
from electrum_firo.transaction import (Transaction, PartialTransaction, PartialTxInput,
                                      PartialTxOutput, TxOutpoint, multisig_script)
from electrum_firo.dash_tx import FiroSparkSpend
from electrum_firo.crypto import sha256d
from electrum_firo.interface import GracefulDisconnect
from electrum_firo.network import UntrustedServerReturnedError
from electrum_firo.util import AddTransactionException, TxMinedInfo
from electrum_firo.verifier import SPV
from electrum_firo.wallet import Imported_Wallet
from electrum_firo.wallet_db import WalletDB

from . import ElectrumTestCase


class TestUnconfirmedSignatures(ElectrumTestCase):
    def setUp(self):
        super().setUp()
        callbacks = mock.patch('electrum_firo.util.trigger_callback')
        callbacks.start()
        self.addCleanup(callbacks.stop)
        self.secret = bytes.fromhex('01' * 32)
        self.pubkey = ecc.ECPrivkey(self.secret).get_public_key_bytes(compressed=True)
        self.address = bitcoin.public_key_to_p2pkh(self.pubkey)
        self.destination = bitcoin.hash160_to_p2pkh(bytes.fromhex('22' * 20))
        self.wallet = Imported_Wallet(
            WalletDB('', manual_upgrades=False), None,
            config=SimpleConfig({'electrum_path': self.electrum_path}))
        self.wallet.import_address(self.address)
        self.funding = self.make_funding(self.address)

    def make_funding(self, address):
        txin = PartialTxInput(prevout=TxOutpoint(bytes(32), 0xffffffff))
        txin.script_sig = b'\x01\x01'
        return Transaction(PartialTransaction.from_io(
            [txin], [PartialTxOutput.from_address_and_value(address, 100000)],
            version=2, locktime=0).serialize())

    def make_spend(self, funding=None):
        funding = funding or self.funding
        txin = PartialTxInput(prevout=TxOutpoint(bytes.fromhex(funding.txid()), 0))
        txin.utxo = funding
        txin.script_type = 'p2pkh'
        txin.pubkeys = [self.pubkey]
        tx = PartialTransaction.from_io(
            [txin], [PartialTxOutput.from_address_and_value(self.destination, 90000)],
            version=2, locktime=0)
        tx.sign({self.pubkey.hex(): (self.secret, True)})
        return Transaction(tx.serialize())

    def receive(self, tx, height=TX_HEIGHT_UNCONFIRMED):
        self.wallet.receive_tx_callback(tx.txid(), tx, height)

    def forged_copy(self, tx):
        forged = copy.deepcopy(tx)
        forged.outputs()[0].scriptpubkey = bytes.fromhex(
            bitcoin.address_to_script(bitcoin.hash160_to_p2pkh(bytes.fromhex('33' * 20))))
        forged.invalidate_ser_cache()
        return Transaction(forged.serialize_to_network())

    def hold_nonstandard_spend(self):
        self.receive(self.funding)
        tx = self.make_spend()
        tx.inputs()[0].script_sig = b'\x00' + tx.inputs()[0].script_sig
        tx.invalidate_ser_cache()
        self.receive(tx, height=100)
        self.assertTrue(self.wallet.is_held_tx(tx.txid()))
        return tx

    def test_valid_outgoing(self):
        self.receive(self.funding)
        tx = self.make_spend()
        self.receive(tx)
        self.assertIsNotNone(self.wallet.db.get_transaction(tx.txid()))
        self.assertEqual([self.address], self.wallet.db.get_txi_addresses(tx.txid()))

    def test_forged_outgoing_cannot_replace_original(self):
        self.receive(self.funding)
        tx = self.make_spend()
        self.receive(tx)
        forged = self.forged_copy(tx)
        with self.assertRaises(AddTransactionException):
            self.receive(forged)
        self.assertIsNone(self.wallet.db.get_transaction(forged.txid()))
        self.assertIsNotNone(self.wallet.db.get_transaction(tx.txid()))
        self.assertEqual(tx.txid(), self.wallet.db.get_spent_outpoint(self.funding.txid(), 0))

    def test_forged_outgoing_without_original(self):
        self.receive(self.funding)
        with self.assertRaises(AddTransactionException):
            self.receive(self.forged_copy(self.make_spend()))
        self.assertIsNone(self.wallet.db.get_spent_outpoint(self.funding.txid(), 0))

    def test_forged_child_before_parent_is_removed(self):
        forged = self.forged_copy(self.make_spend())
        self.receive(forged)
        self.receive(self.funding)
        self.assertIsNone(self.wallet.db.get_transaction(forged.txid()))
        self.assertIsNone(self.wallet.db.get_spent_outpoint(self.funding.txid(), 0))

    def test_valid_child_before_parent(self):
        tx = self.make_spend()
        self.receive(tx)
        self.receive(self.funding)
        self.assertIsNotNone(self.wallet.db.get_transaction(tx.txid()))
        self.assertEqual([self.address], self.wallet.db.get_txi_addresses(tx.txid()))

    def test_claimed_mined_waits_for_proof(self):
        self.receive(self.funding)
        tx = self.make_spend()
        self.receive(tx)
        forged = self.forged_copy(tx)
        self.receive(forged, height=100)
        self.assertTrue(self.wallet.is_held_tx(forged.txid()))
        self.assertIsNone(self.wallet.db.get_transaction(forged.txid()))
        self.assertIsNotNone(self.wallet.db.get_transaction(tx.txid()))
        self.wallet.remove_unverified_tx(forged.txid(), 100)
        self.assertFalse(self.wallet.is_held_tx(forged.txid()))

    def test_proven_transaction_is_added(self):
        tx = self.hold_nonstandard_spend()
        self.assertIsNone(self.wallet.db.get_transaction(tx.txid()))
        with mock.patch('electrum_firo.util.trigger_callback') as callback:
            self.wallet.add_verified_tx(tx.txid(), TxMinedInfo(height=100, txpos=1))
            callback.assert_any_call('wallet_updated', self.wallet)
        self.assertIsNotNone(self.wallet.db.get_transaction(tx.txid()))

    def test_ordinary_mined_transaction_is_not_held(self):
        self.receive(self.funding, height=100)
        self.assertFalse(self.wallet.is_held_tx(self.funding.txid()))
        self.assertIsNotNone(self.wallet.db.get_transaction(self.funding.txid()))

    def test_held_transaction_becomes_unconfirmed(self):
        self.receive(self.funding)
        forged = self.forged_copy(self.make_spend())
        self.receive(forged, height=100)
        with self.assertRaises(AddTransactionException):
            self.receive(forged)
        self.assertFalse(self.wallet.is_held_tx(forged.txid()))

    def test_server_switch_discards_held_transactions(self):
        tx = self.hold_nonstandard_spend()
        self.wallet.clear_held_txs()
        self.wallet.add_verified_tx(tx.txid(), TxMinedInfo(height=100, txpos=1))
        self.assertIsNone(self.wallet.db.get_transaction(tx.txid()))

    def test_proof_error_reconnects_for_held_transaction(self):
        tx = self.hold_nonstandard_spend()

        async def check():
            verifier = mock.Mock(spec=SPV)
            verifier.wallet = self.wallet
            verifier.logger = mock.Mock()
            verifier._network_request_semaphore = asyncio.Semaphore(1)
            verifier.network = mock.Mock()
            verifier.network.get_merkle_for_transaction = mock.AsyncMock(side_effect=
                UntrustedServerReturnedError(original_exception=RPCError(-5, 'not found')))
            verifier.requested_merkle = {tx.txid()}
            with self.assertRaises(GracefulDisconnect):
                await SPV._request_and_verify_single_proof(verifier, tx.txid(), 100)

        loop = asyncio.get_event_loop()
        try:
            asyncio.run(check())
        finally:
            asyncio.set_event_loop(loop)
        self.assertTrue(self.wallet.is_held_tx(tx.txid()))
        self.assertIsNone(self.wallet.db.get_transaction(tx.txid()))

    def test_watch_only_conditional_script(self):
        op = bitcoin.opcodes
        redeem = bytes.fromhex(bitcoin.construct_script([
            op.OP_IF, self.pubkey, op.OP_CHECKSIG, op.OP_ELSE,
            self.pubkey, op.OP_CHECKSIG, op.OP_ENDIF]))
        address = bitcoin.hash160_to_p2sh(bitcoin.hash_160(redeem))
        self.wallet.import_address(address)
        funding = self.make_funding(address)
        self.receive(funding)
        tx = self.make_spend(funding)
        sig = ecc.ECPrivkey(self.secret).sign_transaction(tx._signature_hash(0, redeem, 1))
        tx.inputs()[0].script_sig = bytes.fromhex(bitcoin.construct_script([
            sig + b'\x01', op.OP_1, redeem]))
        tx.invalidate_ser_cache()
        self.assertIsNone(tx.verify_input_signature(0, funding.outputs()[0].scriptpubkey))
        self.receive(tx)
        self.wallet.load_and_cleanup()
        self.assertIsNotNone(self.wallet.db.get_transaction(tx.txid()))

    def test_multisig_push_size_limit(self):
        for count, compressed, valid in ((15, True, True), (8, False, False)):
            with self.subTest(count=count):
                keys = [ecc.ECPrivkey(bytes([i]) * 32).get_public_key_bytes(compressed=compressed)
                        for i in range(1, count + 1)]
                redeem = bytes.fromhex(multisig_script([key.hex() for key in keys], 1))
                address = bitcoin.hash160_to_p2sh(bitcoin.hash_160(redeem))
                funding = self.make_funding(address)
                tx = self.make_spend(funding)
                sig = ecc.ECPrivkey(self.secret).sign_transaction(tx._signature_hash(0, redeem, 1))
                tx.inputs()[0].script_sig = bytes.fromhex(bitcoin.construct_script([
                    0, sig + b'\x01', redeem]))
                self.assertIs(tx.verify_input_signature(0, funding.outputs()[0].scriptpubkey), valid)

    def test_cached_forgery_is_removed_on_startup(self):
        self.receive(self.funding)
        forged = self.forged_copy(self.make_spend())
        with mock.patch.object(self.wallet, '_are_wallet_inputs_valid', return_value=True):
            self.receive(forged)
        self.wallet.load_and_cleanup()
        self.assertIsNone(self.wallet.db.get_transaction(forged.txid()))
        self.assertIsNone(self.wallet.db.get_spent_outpoint(self.funding.txid(), 0))

    def test_invalid_scripts_do_not_bypass_checks(self):
        self.receive(self.funding)
        for script in (b'', b'\x4c\xff', b'\xd3', b'\xc9',
                       bytes.fromhex(bitcoin.construct_script([b'bad\x01', self.pubkey]))):
            with self.subTest(script=script):
                tx = self.make_spend()
                tx.inputs()[0].script_sig = script
                tx.invalidate_ser_cache()
                with self.assertRaises(AddTransactionException):
                    self.receive(tx)

    def test_sighash_all_matches_existing_signer(self):
        tx = PartialTransaction.from_tx(self.make_spend())
        tx.inputs()[0].script_type = 'p2pkh'
        tx.inputs()[0].pubkeys = [self.pubkey]
        script = self.funding.outputs()[0].scriptpubkey
        self.assertEqual(sha256d(bytes.fromhex(tx.serialize_preimage(0))),
                         tx._signature_hash(0, script, 1))

    def test_supported_hash_modes_and_exchange_address(self):
        for script_type in ('p2pkh', 'exp2pkh'):
            script = bytes.fromhex(bitcoin.address_to_script(
                bitcoin.pubkey_to_address(script_type, self.pubkey.hex())))
            for flag in (1, 2, 3, 0x81, 0x82, 0x83):
                with self.subTest(script_type=script_type, flag=flag):
                    tx = self.make_spend()
                    sig = ecc.ECPrivkey(self.secret).sign_transaction(tx._signature_hash(0, script, flag))
                    tx.inputs()[0].script_sig = bytes.fromhex(
                        bitcoin.construct_script([sig + bytes([flag]), self.pubkey]))
                    self.assertTrue(tx.verify_input_signature(0, script))

    def test_multisig_requires_threshold_and_order(self):
        secrets = [bytes([i]) * 32 for i in (1, 2, 3)]
        keys = [ecc.ECPrivkey(s).get_public_key_bytes(compressed=True) for s in secrets]
        redeem = bytes.fromhex(multisig_script([key.hex() for key in keys], 2))
        address = bitcoin.hash160_to_p2sh(bitcoin.hash_160(redeem))
        self.wallet.import_address(address)
        funding = self.make_funding(address)
        self.receive(funding)
        tx = self.make_spend(funding)
        digest = tx._signature_hash(0, redeem, 1)
        sigs = [ecc.ECPrivkey(s).sign_transaction(digest) + b'\x01' for s in secrets]
        for supplied, valid in (([sigs[0], sigs[2]], True), ([sigs[2], sigs[0]], False),
                                ([sigs[0]], False), ([sigs[0], sigs[0]], False)):
            with self.subTest(valid=valid, supplied=supplied):
                tx.inputs()[0].script_sig = bytes.fromhex(bitcoin.construct_script([0, *supplied, redeem]))
                tx.invalidate_ser_cache()
                if valid:
                    self.receive(tx)
                    self.assertIsNotNone(self.wallet.db.get_transaction(tx.txid()))
                else:
                    with self.assertRaises(AddTransactionException):
                        self.receive(tx)

    def test_special_payload_is_signed(self):
        self.receive(self.funding)
        tx = PartialTransaction.from_tx(self.make_spend())
        tx.version, tx.tx_type = 3, 9
        tx.extra_payload = FiroSparkSpend(b'payload')
        txin = tx.inputs()[0]
        txin.script_sig = None
        txin.script_type = 'p2pkh'
        txin.pubkeys = [self.pubkey]
        txin.utxo = self.funding
        tx.sign({self.pubkey.hex(): (self.secret, True)})
        signed = Transaction(tx.serialize())
        self.receive(signed)
        signed.extra_payload.sparkData = b'changed'
        signed.invalidate_ser_cache()
        with self.assertRaises(AddTransactionException):
            self.receive(signed)

    def test_partial_input_metadata_cannot_hide_ownership(self):
        self.receive(self.funding)
        raw = self.forged_copy(self.make_spend())
        forged = PartialTransaction.from_tx(raw)
        forged.inputs()[0].script_sig = raw.inputs()[0].script_sig
        forged.inputs()[0]._trusted_address = self.destination
        with self.assertRaises(AddTransactionException):
            self.wallet.add_transaction(forged, allow_unrelated=True)

    def test_other_participants_are_not_checked(self):
        self.receive(self.funding)
        other = self.make_funding(self.destination)
        self.receive(other)
        tx = PartialTransaction.from_tx(self.make_spend())
        foreign = PartialTxInput(prevout=TxOutpoint(bytes.fromhex(other.txid()), 0))
        foreign.script_sig = b'not checked'
        tx.inputs().append(foreign)
        own = tx.inputs()[0]
        own.script_sig = None
        own.script_type = 'p2pkh'
        own.pubkeys = [self.pubkey]
        own.utxo = self.funding
        tx.sign({self.pubkey.hex(): (self.secret, True)})
        self.receive(Transaction(tx.serialize()))
        self.assertIsNotNone(self.wallet.db.get_transaction(tx.txid()))
