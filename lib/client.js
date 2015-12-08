// Copyright 2015 Joyent, Inc.

var assert = require('assert-plus');
var sshpk = require('sshpk');
var util = require('util');
var errs = require('./errors');
var AgentProtocolError = errs.AgentProtocolError;

var ClientFSM = require('./client-fsm');

function Client(opts) {
	ClientFSM.call(this, opts);
}
util.inherits(Client, ClientFSM);

Client.prototype.listKeys = function (opts, cb) {
	if (typeof (opts) === 'function' && cb === undefined) {
		cb = opts;
		opts = {};
	}
	assert.object(opts, 'options');
	assert.optionalNumber(opts.timeout, 'options.timeout');
	var timeout = opts.timeout || this.timeout;
	assert.func(cb, 'callback');

	var frame = {type: 'request-identities'};
	var resps = ['identities-answer'];

	this.doRequest(frame, resps, timeout, function (err, resp) {
		if (err) {
			cb(err);
			return;
		}

		var keys = [];
		for (var i = 0; i < resp.identities.length; ++i) {
			var id = resp.identities[i];
			try {
				var key = sshpk.parseKey(id.key, 'rfc4253');
				key.comment = id.comment;
				keys.push(key);
			} catch (e) {
				var err2 = new AgentProtocolError(resp,
				    'Failed to parse key in ssh-agent ' +
				    'response: ' + e.name + ': ' + e.message);
				cb(err2);
				return;
			}
		}

		cb(null, keys);
	});
};

Client.prototype.sign = function (key, data, opts, cb) {
	assert.object(key, 'key');
	if (typeof (data) === 'string')
		data = new Buffer(data);
	assert.buffer(data, 'data');
	assert.ok(sshpk.Key.isKey(key, [1, 3]), 'key must be an sshpk.Key');
	if (typeof (opts) === 'function' && cb === undefined) {
		cb = opts;
		opts = {};
	}
	assert.object(opts, 'options');
	assert.optionalNumber(opts.timeout, 'options.timeout');
	assert.func(cb, 'callback');
	var timeout = opts.timeout || this.timeout;

	var frame = {
		type: 'sign-request',
		publicKey: key.toBuffer('rfc4253'),
		data: data,
		flags: []
	};
	var resps = ['failure', 'sign-response'];

	this.doRequest(frame, resps, timeout, function (err, resp) {
		if (err) {
			cb(err);
			return;
		}

		if (resp.type === 'failure') {
			cb(new Error('SSH agent returned failure, no ' +
			    'reason given'));
			return;
		}

		try {
			var sig = sshpk.parseSignature(resp.signature,
			    key.type, 'ssh');

			/* Emulate the openssh hash algorithm choice */
			switch (key.type) {
			case 'rsa':
			case 'dsa':
				sig.hashAlgorithm = 'sha1';
				break;
			case 'ecdsa':
				if (key.size <= 256)
					sig.hashAlgorithm = 'sha256';
				else if (key.size <= 384)
					sig.hashAlgorithm = 'sha384';
				else
					sig.hashAlgorithm = 'sha512';
				break;
			default:
				/* what */
				break;
			}
		} catch (e) {
			var err2 = new AgentProtocolError(resp,
			    'Failed to parse signature in ssh-agent ' +
			    'response: ' + e.name + ': ' + e.message);
			cb(err2);
			return;
		}

		cb(null, sig);
	});
};

Client.prototype.addKey = function (key, opts, cb) {
	assert.object(key, 'key');
	assert.ok(sshpk.PrivateKey.isPrivateKey(key, [1, 2]),
	    'key must be an sshpk.PrivateKey');
	if (typeof (opts) === 'function' && cb === undefined) {
		cb = opts;
		opts = {};
	}
	assert.object(opts, 'options');
	assert.optionalNumber(opts.timeout, 'options.timeout');
	assert.optionalNumber(opts.expires, 'options.expires');
	var timeout = opts.timeout || this.timeout;
	assert.func(cb, 'callback');

	var frame = {
		type: 'add-identity',
		privateKey: key.toBuffer('rfc4253'),
		comment: key.comment || ''
	};
	if (opts.expires !== undefined) {
		frame.type = 'add-identity-constrained';
		frame.constraints = [
			{type: 'lifetime', seconds: opts.expires}
		];
	}
	var resps = ['success', 'failure'];

	this.doRequest(frame, resps, timeout, function (err, resp) {
		if (err) {
			cb(err);
			return;
		}
		if (resp.type === 'failure') {
			cb(new Error('SSH agent returned failure'));
			return;
		}
		cb(null);
	});
};

Client.prototype.removeKey = function (key, opts, cb) {
	assert.object(key, 'key');
	assert.ok(sshpk.Key.isKey(key, [1, 3]), 'key must be an sshpk.Key');
	if (typeof (opts) === 'function' && cb === undefined) {
		cb = opts;
		opts = {};
	}
	assert.object(opts, 'options');
	assert.optionalNumber(opts.timeout, 'options.timeout');
	var timeout = opts.timeout || this.timeout;
	assert.func(cb, 'callback');

	var frame = {
		type: 'remove-identity',
		publicKey: key.toBuffer('rfc4253')
	};
	var resps = ['success', 'failure'];

	this.doRequest(frame, resps, timeout, function (err, resp) {
		if (err) {
			cb(err);
			return;
		}
		if (resp.type === 'failure') {
			cb(new Error('SSH agent returned failure'));
			return;
		}
		cb(null);
	});
};

Client.prototype.removeAllKeys = function (opts, cb) {
	if (typeof (opts) === 'function' && cb === undefined) {
		cb = opts;
		opts = {};
	}
	assert.object(opts, 'options');
	assert.optionalNumber(opts.timeout, 'options.timeout');
	var timeout = opts.timeout || this.timeout;
	assert.func(cb, 'callback');

	var frame = {type: 'remove-all-identities'};
	var resps = ['success', 'failure'];

	this.doRequest(frame, resps, timeout, function (err, resp) {
		if (err) {
			cb(err);
			return;
		}
		if (resp.type === 'failure') {
			cb(new Error('SSH agent returned failure'));
			return;
		}
		cb(null);
	});
};

Client.prototype.lock = function (pw, opts, cb) {
	assert.string(pw, 'password');
	if (typeof (opts) === 'function' && cb === undefined) {
		cb = opts;
		opts = {};
	}
	assert.object(opts, 'options');
	assert.optionalNumber(opts.timeout, 'options.timeout');
	var timeout = opts.timeout || this.timeout;
	assert.func(cb, 'callback');

	var frame = {
		type: 'lock',
		password: pw
	};
	var resps = ['success', 'failure'];

	this.doRequest(frame, resps, timeout, function (err, resp) {
		if (err) {
			cb(err);
			return;
		}
		if (resp.type === 'failure') {
			cb(new Error('SSH agent returned failure'));
			return;
		}
		cb(null);
	});
};

Client.prototype.unlock = function (pw, opts, cb) {
	assert.string(pw, 'password');
	if (typeof (opts) === 'function' && cb === undefined) {
		cb = opts;
		opts = {};
	}
	assert.object(opts, 'options');
	assert.optionalNumber(opts.timeout, 'options.timeout');
	var timeout = opts.timeout || this.timeout;
	assert.func(cb, 'callback');

	var frame = {
		type: 'unlock',
		password: pw
	};
	var resps = ['success', 'failure'];

	this.doRequest(frame, resps, timeout, function (err, resp) {
		if (err) {
			cb(err);
			return;
		}
		if (resp.type === 'failure') {
			cb(new Error('SSH agent returned failure'));
			return;
		}
		cb(null);
	});
};


module.exports = Client;
