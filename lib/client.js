// Copyright 2015 Joyent, Inc.

var assert = require('assert-plus');
var crypto = require('crypto');
var sshpk = require('sshpk');
var util = require('util');
var EventEmitter = require('events').EventEmitter;
var net = require('net');
var errs = require('./errors');
var AgentProtocolError = errs.AgentProtocolError;

var protoStreams = require('./protocol-streams');
var AgentEncodeStream = protoStreams.AgentEncodeStream;
var AgentDecodeStream = protoStreams.AgentDecodeStream;

function Client(opts) {
	EventEmitter.call(this);
	if (opts === undefined)
		opts = {};
	assert.object(opts, 'options');
	var sockPath = opts.socketPath;
	if (sockPath === undefined)
		sockPath = process.env['SSH_AUTH_SOCK'];
	assert.string(sockPath, 'options.socketPath or $SSH_AUTH_SOCK');
	assert.optionalNumber(opts.timeout, 'options.timeout');

	this.sockPath = sockPath;
	this.timeout = opts.timeout || 2000;
	this.state = 'disconnected';
	this.requestQueue = [];
}
util.inherits(Client, EventEmitter);

Object.defineProperties(Client.prototype, {
	sockPath: { writable: true },
	timeout: { writable: true, enumerable: true },
	state: { writable: true, enumerable: true },
	requestQueue: { writable: true },
	socket: { writable: true, configurable: true },
	request: { writable: true, configurable: true },
	encodeStream: { writable: true, configurable: true },
	decodeStream: { writable: true, configurable: true }
});

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
	assert.ok(key instanceof sshpk.Key, 'key must be an sshpk.Key');
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
	assert.ok(key instanceof sshpk.PrivateKey,
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
	assert.ok(key instanceof sshpk.Key, 'key must be an sshpk.Key');
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

Client.prototype.doRequest = function (sendFrame, respTypes, timeout, cb) {
	assert.object(sendFrame);
	assert.arrayOfString(respTypes);
	assert.number(timeout);
	assert.func(cb);

	var self = this;

	var req = new EventEmitter();
	req.retries = 2;

	req.on('send', function (s) {
		req.timeoutId = setTimeout(function () {
			if (req.timeoutId === null)
				return;
			self.disconnect();
			req.emit('error', new Error('Timeout waiting for ' +
			    'response from SSH agent (' + timeout + ' ms)'));
			delete (req.timeoutId);
		}, timeout);
		s.write(sendFrame);
	});

	req.on('error', function (err) {
		if (req.timeoutId !== undefined) {
			clearTimeout(req.timeoutId);
			delete (req.timeoutId);
		}

		self.finishRequest(req);

		if (req.retries > 0) {
			req.retries--;
			self.enqueueRequest(req);
			return;
		}

		cb(err);
	});

	req.on('frame', function (frame) {
		if (req.timeoutId !== undefined) {
			clearTimeout(req.timeoutId);
			delete (req.timeoutId);
		}
		self.finishRequest(req);

		if (respTypes.indexOf(frame.type) === -1) {
			self.disconnect();
			cb(new AgentProtocolError(frame, 'Frame received ' +
			    'from agent out of order. Got a ' + frame.type +
			    ', expected a ' + respTypes.join(' or ')));
			return;
		}

		cb(null, frame);
	});

	this.enqueueRequest(req);
};

Client.prototype.enqueueRequest = function (req) {
	assert.object(req);
	assert.ok(req instanceof EventEmitter);

	this.requestQueue.push(req);
	this.nextRequest();
};

Client.prototype.finishRequest = function () {
	assert.object(this.request);
	delete (this.request);
	if (this.requestQueue.length > 0)
		this.nextRequest();
	else if (this.socket)
		this.socket.unref();
};

Client.prototype.nextRequest = function () {
	if (!this.request && this.requestQueue.length > 0) {
		this.request = this.requestQueue.shift();
		if (this.socket)
			this.socket.ref();

		var self = this;
		this.connect(function () {
			self.request.emit('send', self.encodeStream);
		});
	}
};

Client.prototype.connect = function (cb) {
	assert.optionalFunc(cb, 'callback');

	var self = this;

	if (this.state === 'connected') {
		if (cb)
			cb(null);
		return;
	} else if (this.state === 'connecting') {
		if (cb)
			this.once('connect', cb);
		return;
	}
	assert.strictEqual(this.state, 'disconnected');

	this.state = 'connecting';
	if (cb)
		this.once('connect', cb);

	var sock = this.socket = net.connect(this.sockPath);

	var ds = this.decodeStream = new AgentDecodeStream({role: 'client'});
	sock.pipe(ds);

	var es = this.encodeStream = new AgentEncodeStream({role: 'client'});
	es.pipe(this.socket);

	var connTimeoutId = setTimeout(function () {
		if (!connTimeoutId)
			return;

		var err = new Error('ssh-agent connect timed out');
		if (self.request)
			self.request.emit('error', err);
		else
			self.emit('error', err);
		connTimeoutId = undefined;
	}, this.timeout);

	sock.on('connect', function () {
		if (connTimeoutId) {
			clearTimeout(connTimeoutId);
			connTimeoutId = undefined;
		}
		self.state = 'connected';
		self.emit('connect');
	});
	sock.on('error', function (err) {
		self.disconnect();
		if (self.request)
			self.request.emit('error', err);
		else
			self.emit('error', err);
	});
	sock.on('close', function () {
		if (self.state === 'connected' && sock === self.socket)
			self.disconnect();
	});

	ds.on('readable', function () {
		if (ds !== self.decodeStream)
			return;
		var frame;
		while ((frame = ds.read())) {
			if (self.request) {
				self.request.emit('frame', frame);
			} else {
				self.emit('error', new AgentProtocolError(
				    undefined, 'Out of order frame received: ' +
				    frame.type));
				self.disconnect();
			}
		}
	});
	ds.on('error', function (err) {
		self.disconnect();
		if (self.request)
			self.request.emit('error', err);
		else
			self.emit('error', err);
	});
	es.on('error', function (err) {
		assert.object(self.request);
		self.request.retries = 0;
		self.request.emit('error', err);
	});
};

Client.prototype.disconnect = function (cb) {
	assert.optionalFunc(cb, 'callback');
	assert.strictEqual(this.state, 'connected', 'client must be connected');

	this.socket.destroy();
	this.state = 'disconnected';
	delete (this.socket);
	delete (this.decodeStream);
	delete (this.encodeStream);
	this.emit('disconnect');
};

module.exports = Client;
