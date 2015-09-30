// Copyright 2015 Joyent, Inc.  All rights reserved.

var test = require('tape').test;

var Agent = require('./ssh-agent-ctl');
var sshpk = require('sshpk');
var path = require('path');
var fs = require('fs');

var sshpkAgent = require('../lib/index');

var agent;
var testDir = __dirname;

var ID_RSA_FP = sshpk.parseFingerprint(
    'SHA256:tT5wcGMJkBzNu+OoJYEgDCwIcDAIFCUahAmuTT4qC3s');
var ID_ECDSA_FP = sshpk.parseFingerprint(
    'SHA256:e34c67Npv31uMtfVUEBJln5aOcJugzDaYGsj1Uph5DE');
var ID_DSA_FP = sshpk.parseFingerprint(
    'SHA256:PCfwpK62grBWrAJceLetSNv9CTrX8yoD0miKf11DBG8');

test('setup', function (t) {
	delete (process.env['SSH_AGENT_PID']);
	delete (process.env['SSH_AUTH_SOCK']);
	t.end();
});

test('agent setup', function (t) {
	agent = new Agent();
	agent.on('open', function () {
		agent.importEnv();
		t.end();
	});
	agent.on('error', function (err) {
		console.log(err);
		agent = undefined;
		t.end();
	});
});

var client;

test('Client connect', function (t) {
	client = new sshpkAgent.Client();
	t.ok(client);
	client.connect(function () {
		t.end();
	});
});

test('Client can add an RSA key', function (t) {
	var pem = fs.readFileSync(path.join(testDir, 'id_rsa'));
	var pk = sshpk.parsePrivateKey(pem, 'pem', 'test/id_rsaaaaa');
	client.addKey(pk, function (err) {
		t.error(err);

		client.listKeys(function (err, keys) {
			t.error(err);
			t.equal(keys.length, 1);
			t.ok(ID_RSA_FP.matches(keys[0]));
			t.strictEqual(keys[0].comment, 'test/id_rsaaaaa');
			t.end();
		});
	});
});

test('Client can add a DSA key', function (t) {
	var pem = fs.readFileSync(path.join(testDir, 'id_dsa'));
	var pk = sshpk.parsePrivateKey(pem, 'pem', 'test/id_dsa');
	client.addKey(pk, function (err) {
		t.error(err);

		client.listKeys(function (err, keys) {
			t.error(err);
			t.equal(keys.length, 2);
			t.ok(ID_DSA_FP.matches(keys[1]));
			t.strictEqual(keys[1].comment, 'test/id_dsa');
			t.end();
		});
	});
});

test('Client can add an ECDSA key', function (t) {
	var pem = fs.readFileSync(path.join(testDir, 'id_ecdsa'));
	var pk = sshpk.parsePrivateKey(pem, 'pem', 'test/id_ecdsa');
	client.addKey(pk, function (err) {
		t.error(err);

		client.listKeys(function (err, keys) {
			t.error(err);
			t.equal(keys.length, 3);
			t.ok(ID_ECDSA_FP.matches(keys[2]));
			t.strictEqual(keys[2].comment, 'test/id_ecdsa');
			t.end();
		});
	});
});

test('Client can remove a key', function (t) {
	client.listKeys(function (err, keys) {
		t.error(err);
		t.equal(keys.length, 3);

		client.removeKey(keys[1], function (err) {
			t.error(err);

			client.listKeys(function (err, keys) {
				t.error(err);
				t.equal(keys.length, 2);
				t.end();
			});
		});
	});
});

test('Client can remove all keys', function (t) {
	client.removeAllKeys(function (err) {
		t.error(err);

		client.listKeys(function (err, keys) {
			t.error(err);
			t.equal(keys.length, 0);
			t.end();
		});
	});
});

test('Client can lock the agent', function (t) {
	client.lock('foobar', function (err) {
		t.error(err);

		var pem = fs.readFileSync(path.join(testDir, 'id_dsa'));
		var pk = sshpk.parsePrivateKey(pem, 'pem', 'test/id_dsa');
		client.addKey(pk, function (err) {
			t.ok(err);
			t.ok(err instanceof Error);
			t.end();
		});
	});
});

test('Client can unlock the agent', function (t) {
	client.unlock('foobar', function (err) {
		t.error(err);

		var pem = fs.readFileSync(path.join(testDir, 'id_dsa'));
		var pk = sshpk.parsePrivateKey(pem, 'pem', 'test/id_dsa');
		client.addKey(pk, function (err) {
			t.error(err);
			t.end();
		});
	});
});

test('Client can add an expiring key', function (t) {
	var pem = fs.readFileSync(path.join(testDir, 'id_ecdsa'));
	var pk = sshpk.parsePrivateKey(pem, 'pem', 'test/id_ecdsa');
	client.addKey(pk, {expires: 2}, function (err) {
		t.error(err);

		client.listKeys(function (err, keys) {
			t.error(err);
			t.equal(keys.length, 2);
			t.ok(ID_ECDSA_FP.matches(keys[1]));

			setTimeout(function () {
				client.listKeys(function (err, keys) {
					t.error(err);
					t.equal(keys.length, 1);
					t.notOk(ID_ECDSA_FP.matches(keys[0]));
					t.end();
				});
			}, 2000);
		});
	});
});

test('agent teardown', function (t) {
	t.ok(agent);
	client = undefined;
	agent.close(function () {
		t.end();
	});
});
