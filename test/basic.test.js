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
var ID_ED25519_FP = sshpk.parseFingerprint(
    'SHA256:Mu6PkebM4ksg1M+dmhz+vw7gYPrKzeO2bCVqIEKKsis');

test('setup', function (t) {
	delete (process.env['SSH_AGENT_PID']);
	delete (process.env['SSH_AUTH_SOCK']);
	t.end();
});

test('Client throws with no socket', function (t) {
	t.throws(function () {
		new sshpkAgent.Client();
	});
	t.end();
});

test('agent setup', function (t) {
	agent = new Agent();
	agent.on('open', function () {
		t.end();
	});
	agent.on('error', function (err) {
		console.log(err);
		agent = undefined;
		t.end();
	});
});

test('Client takes path to socket in constructor', function (t) {
	var c = new sshpkAgent.Client({
		socketPath: agent.env['SSH_AUTH_SOCK']
	});
	t.ok(c);
	t.end();
});

test('Client takes path to socket from environment', function (t) {
	agent.importEnv();
	var c = new sshpkAgent.Client();
	t.ok(c);
	t.end();
});

test('Client can connect', function (t) {
	var c = new sshpkAgent.Client();
	c.ref();
	c.connect(function () {
		t.ok(c);
		t.ok(/^connected($|[.])/.test(c.getState()));
		c.unref();
		t.end();
	});
});

test('Client can list keys when empty', function (t) {
	var c = new sshpkAgent.Client();
	c.listKeys(function (err, keys) {
		t.error(err);
		t.ok(keys instanceof Array);
		t.equal(keys.length, 0);
		t.end();
	});
});

test('Client can list keys with one key loaded', function (t) {
	var c = new sshpkAgent.Client();
	agent.addKey(path.join(testDir, 'id_rsa'), function (err) {
		t.error(err);
		c.listKeys(function (err, keys) {
			t.error(err);
			t.ok(keys instanceof Array);
			t.equal(keys.length, 1);

			t.ok(keys[0] instanceof sshpk.Key);
			t.strictEqual(keys[0].type, 'rsa');
			t.strictEqual(keys[0].size, 1024);
			t.ok(ID_RSA_FP.matches(keys[0]));
			t.end();
		});
	});
});

test('Client can list multiple keys', function (t) {
	var c = new sshpkAgent.Client();
	agent.addKey(path.join(testDir, 'id_ecdsa'), function (err) {
		t.error(err);
		c.listKeys(function (err, keys) {
			t.error(err);
			t.ok(keys instanceof Array);
			t.equal(keys.length, 2);

			t.ok(keys[1] instanceof sshpk.Key);
			t.strictEqual(keys[1].type, 'ecdsa');
			t.ok(ID_ECDSA_FP.matches(keys[1]));
			t.end();
		})
	});
});

/* Connection re-use disabled on node 0.8 because it lacks unref() */
if (!process.version.match(/^v0\.[0-8]\./)) {
	test('Client can re-use connection', function (t) {
		var c = new sshpkAgent.Client();
		c.listKeys(function (err, keys) {
			t.error(err);
			t.strictEqual(c.getState(), 'connected.busy');
			c.listKeys(function (err2, keys2) {
				t.error(err2);
				t.end();
			});
		})
	});

	test('multiple requests while stopped', function (t) {
		var resp = 0;
		var sent = 0;
		var c = new sshpkAgent.Client();
		agent.signal('stop', function (err) {
			t.error(err);

			for (var i = 0; i < 10; ++i) {
				++sent;
				setTimeout(function () {
					c.listKeys(function (err, keys) {
						t.error(err);
						if (++resp >= sent)
							t.end();
					});
				}, i*50);
			}
			setTimeout(function () {
				agent.signal('cont', function (err) {
					t.error(err);
				});
			}, 250);
		});
	});
}

test('Client queues up requests', function (t) {
	var c = new sshpkAgent.Client();
	var n = 0;

	function callback(err, keys) {
		t.error(err);
		if (++n >= 10)
			t.end();
	}

	for (var i = 0; i < 10; ++i)
		c.listKeys(callback);
});

test('Client can\'t sign with an unknown key', function (t) {
	var c = new sshpkAgent.Client();
	var key = sshpk.parseKey(
	    fs.readFileSync(path.join(testDir, 'id_ecdsa2')), 'pem');
	c.sign(key, 'foobar', function (err, sig) {
		t.ok(err);
		t.notStrictEqual(err.message.indexOf('failure'), -1);
		t.end();
	});
});

test('Client can sign data with an rsa key', function (t) {
	var c = new sshpkAgent.Client();
	c.listKeys(function (err, keys) {
		t.error(err);

		var key = keys[0];
		t.strictEqual(key.type, 'rsa');
		t.ok(ID_RSA_FP.matches(key));

		c.sign(key, 'foobar', function (err, sig) {
			t.error(err);
			t.ok(sig);
			t.ok(sig instanceof sshpk.Signature);

			t.strictEqual(sig.hashAlgorithm, 'sha1');

			var v = key.createVerify('sha1');
			v.update('foobar');
			t.ok(v.verify(sig));

			t.end();
		});
	});
});

test('Client can sign data with an ecdsa key', function (t) {
	var c = new sshpkAgent.Client();
	c.listKeys(function (err, keys) {
		t.error(err);

		var key = keys[1];
		t.strictEqual(key.type, 'ecdsa');
		t.ok(ID_ECDSA_FP.matches(key));

		c.sign(key, 'foobar', function (err, sig) {
			t.error(err);
			t.ok(sig);
			t.ok(sig instanceof sshpk.Signature);

			t.strictEqual(sig.hashAlgorithm, 'sha384');

			var v = key.createVerify('sha384');
			v.update('foobar');
			t.ok(v.verify(sig));

			t.end();
		});
	});
});

test('Client can sign data with an ed25519 key', function (t) {
	var c = new sshpkAgent.Client();
	agent.addKey(path.join(testDir, 'id_ed25519'), function (err) {
		t.error(err);
		c.listKeys(function (err, keys) {
			t.error(err);

			var key = keys[2];
			t.strictEqual(key.type, 'ed25519');
			t.ok(ID_ED25519_FP.matches(key));

			c.sign(key, 'foobar', function (err, sig) {
				t.error(err);
				t.ok(sig);
				t.ok(sig instanceof sshpk.Signature);

				t.strictEqual(sig.hashAlgorithm, 'sha512');

				var v = key.createVerify('sha512');
				v.update('foobar');
				t.ok(v.verify(sig));

				t.end();
			});
		});
	});
});

test('Client can sign data with a dsa key', function (t) {
	var c = new sshpkAgent.Client();
	agent.addKey(path.join(testDir, 'id_dsa'), function (err) {
		t.error(err);

		c.listKeys(function (err, keys) {
			t.error(err);

			var key = keys[3];
			t.strictEqual(key.type, 'dsa');
			t.ok(ID_DSA_FP.matches(key));

			c.sign(key, 'foobar', function (err, sig) {
				t.error(err);
				t.ok(sig);
				t.ok(sig instanceof sshpk.Signature);

				t.strictEqual(sig.hashAlgorithm, 'sha1');

				var v = key.createVerify('sha1');
				v.update('foobar');
				t.ok(v.verify(sig));

				t.end();
			});
		});
	});
});

var c, c2;

test('pre-create Clients before stop/teardown', function (t) {
	c = new sshpkAgent.Client();
	c2 = new sshpkAgent.Client();
	c.connect(function () {
		t.end();
	});
});

test('agent stop', function (t) {
	agent.signal('stop', function (err) {
		t.error(err);
		t.end();
	});
});

test('connected Client times out to stopped agent', function (t) {
	c.listKeys({timeout: 500}, function (err, keys) {
		t.ok(err);
		t.notStrictEqual(err.message.toLowerCase().
		    indexOf('timeout'), -1);
		t.end();
	});
});

test('disconnected Client can\'t connect to stopped agent', function (t) {
	c2.listKeys({timeout: 1000}, function (err, keys) {
		t.ok(err);
		t.end();
	});
});

test('agent resume, client recovers from a socket error', function (t) {
	c.listKeys({timeout: 500}, function (err, keys) {
		t.error(err);
		t.equal(keys.length, 4);
		t.end();
	});
	c.c_socket.emit('error', new Error('dummy error'));
	agent.signal('cont', function (err) {
		t.error(err);
	});
});

test('timed out Client reconnects and works', function (t) {
	c.listKeys({timeout: 1000}, function (err, keys) {
		t.error(err);
		t.equal(keys.length, 4);
		t.end();
	});
});

test('disconnected Client reconnects and works', function (t) {
	c2.listKeys({timeout: 1000}, function (err, keys) {
		t.error(err);
		t.equal(keys.length, 4);
		t.end();
	});
});

test('agent teardown', function (t) {
	t.ok(agent);
	agent.close(function () {
		t.end();
	});
});
