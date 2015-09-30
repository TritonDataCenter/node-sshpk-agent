// Copyright 2015 Joyent, Inc.  All rights reserved.

var test = require('tape').test;

var sshpk = require('sshpk');
var pstr = require('../lib/protocol-streams');
var AgentEncodeStream = pstr.AgentEncodeStream;
var AgentDecodeStream = pstr.AgentDecodeStream;
var fs = require('fs');
var path = require('path');

var testDir = __dirname;

var EX_SIGN_REQ = 'AAAAIQ0AAAAPcHVibGljIGtleSBoZXJlAAAABWFiY2RlAAAAAA==';

var enc, dec;

test('setup streams', function (t) {
	enc = new AgentEncodeStream({role: 'client'});
	dec = new AgentDecodeStream({role: 'agent'});
	t.end();
});

test('enc sign-request empty', function (t) {
	enc.once('error', function (err) {
		t.ok(err);
		t.ok(err instanceof Error);
		t.strictEqual(dec.read(), null);
		t.end();
	});
	enc.write({type: 'sign-request'});
});

test('enc sign-request invalid types', function (t) {
	enc.once('error', function (err) {
		t.ok(err);
		t.ok(err instanceof Error);
		t.strictEqual(dec.read(), null);
		t.end();
	});
	enc.write({
		type: 'sign-request',
		publicKey: 'I am not a buffer',
		data: new Buffer(5),
		flags: []
	});
});

test('enc valid sign-request', function (t) {
	enc.once('readable', function () {
		var data = enc.read();
		t.strictEqual(enc.read(), null);
		t.strictEqual(data.toString('base64'), EX_SIGN_REQ);
		t.end();
	});
	enc.write({
		type: 'sign-request',
		publicKey: new Buffer('public key here'),
		data: new Buffer('abcde'),
		flags: []
	});
});

test('dec zero length req', function (t) {
	dec.once('error', function (err) {
		t.ok(err);
		t.ok(err instanceof Error);
		t.strictEqual(dec.read(), null);
		t.end();
	});
	dec.write(new Buffer('00000000', 'hex'));
});

test('dec unknown frame', function (t) {
	dec.once('error', function (err) {
		t.ok(err);
		t.ok(err instanceof Error);
		t.strictEqual(dec.read(), null);
		t.end();
	});
	dec.write(new Buffer('00000001ff', 'hex'));
});

test('dec req-ids frame', function (t) {
	dec.once('readable', function () {
		var f = dec.read();
		t.ok(f);
		t.strictEqual(null, dec.read());
		t.strictEqual(f.type, 'request-identities');
		t.end();
	});
	dec.write(new Buffer('000000010b', 'hex'));
});

test('setup loopback', function (t) {
	enc.pipe(dec);
	t.end();
});

test('loopback request-identities', function (t) {
	dec.once('readable', function () {
		var frame = dec.read();
		t.ok(frame);
		t.strictEqual(dec.read(), null);
		t.strictEqual(frame.type, 'request-identities');
		t.end();
	});
	enc.write({type: 'request-identities'});
});

test('loopback add-identity', function (t) {
	var pem = fs.readFileSync(path.join(testDir, 'id_rsa'));
	var pk = sshpk.parsePrivateKey(pem, 'pem');
	var pkData = pk.toBuffer('rfc4253');
	dec.once('readable', function () {
		var frame = dec.read();
		t.ok(frame);
		t.strictEqual(dec.read(), null);
		t.strictEqual(frame.type, 'add-identity');
		t.ok(frame.privateKey instanceof Buffer);
		t.strictEqual(frame.comment, 'test');
		t.strictEqual(frame.privateKey.length, pkData.length);
		var pk2 = sshpk.parsePrivateKey(frame.privateKey, 'rfc4253');
		t.ok(pk.fingerprint('sha256').matches(pk2));
		t.end();
	});
	enc.write({
		type: 'add-identity',
		privateKey: pkData,
		comment: 'test'
	});
});
