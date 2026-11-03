'use strict';
// Cross-implementation checks: the JavaScript codec must produce byte-for-byte the frames the
// Python test client produced against the running C gateway.
const test = require('node:test');
const assert = require('node:assert');
const tg = require('../lib/telegram');

const KEY1 = Buffer.from('6d65726368616e742d312d64656d6f2d6b65792d303030303030303030303030', 'hex');

test('echo request matches the frame captured from the Python client', () => {
  const frame = tg.encode({ msg_type: '0800', merchant_id: 'M000000001', terminal_id: 'T0000001', trace_no: '865668',
    tx_datetime: '20261103002747' }, KEY1);
  assert.strictEqual(frame, '0080080001M000000001T00000018656682026110300274700006762A33625A62B6AF6A5094E3016385B');
});

test('echo response produced by the C gateway decodes and its MAC verifies', () => {
  const resp = '0080081001M000000001T0000001865668202611030027470000F1BE761512CC6BCF4E8CB3A7D4073AC6';
  const d = tg.decode(resp);
  assert.strictEqual(d.msg_type, '0810');
  assert.strictEqual(d.resp_code, '0000');
  assert.ok(tg.verify(resp, KEY1));
  assert.ok(!tg.verify(resp.replace('0000F1', '1001F1'), KEY1), 'changing the response code breaks the MAC');
});

test('approval request layout: 144 bytes, padded fields', () => {
  const f = tg.encode({ msg_type: '0200', merchant_id: 'M000000001', terminal_id: 'T0000001', trace_no: '000123',
    tx_datetime: '20261103101500', order_no: 'ORD-20261103-0001', card_no: '4111111111111111', expiry: '2912',
    amount: 15000, installment: '00', currency: 'KRW' }, KEY1);
  assert.strictEqual(f.length, 144);
  assert.strictEqual(f.slice(0, 4), '0140');
  assert.strictEqual(f.slice(4 + 48 + 20, 4 + 48 + 39), '4111111111111111   ');
  assert.strictEqual(f.slice(4 + 48 + 43, 4 + 48 + 55), '000000015000');
});

test('values that do not fit are refused instead of silently cut', () => {
  assert.throws(() => tg.encode({ msg_type: '0200', merchant_id: 'M0000000011', order_no: 'x', amount: 1 }, KEY1));
  assert.throws(() => tg.encode({ msg_type: '0200', merchant_id: 'M000000001', order_no: '주문', amount: 1 }, KEY1));
});
