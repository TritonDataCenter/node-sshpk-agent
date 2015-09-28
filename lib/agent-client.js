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

function AgentClient(opts) {
	EventEmitter.call(this);
	if (opts === undefined)
		opts = {};
	assert.object(opts, 'options');
	var sockPath = opts.socketPath;
	if (sockPath === undefined)
		sockPath = process.env['SSH_AUTH_SOCK'];
	assert.string(sockPath, 'options.socketPath or $SSH_AUTH_SOCK');
	assert.optionalNumber(opts.timeout, 'options.timeout');

	Object.defineProperties(this, {
		sockPath: { value: sockPath },
		timeout: { enumerable: true, value: opts.timeout || 5000 },
		state: { enumerable: true, writable: true,
		    value: 'disconnected' },
		requestQueue: { value: [] },
		socket: { writable: true, configurable: true },
		request: { writable: true, configurable: true },
		encodeStream: { writable: true, configurable: true },
		decodeStream: { writable: true, configurable: true }
	});
}
util.inherits(AgentClient, EventEmitter);

AgentClient.prototype.listKeys = function (opts, cb) {
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

AgentClient.prototype.sign = function (key, data, opts, cb) {
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

AgentClient.prototype.remove = function (key, opts, cb) {
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

AgentClient.prototype.removeAll = function (opts, cb) {
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

AgentClient.prototype.lock = function (pw, opts, cb) {
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

AgentClient.prototype.unlock = function (pw, opts, cb) {
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

AgentClient.prototype.doRequest = function (sendFrame, respTypes, timeout, cb) {
	assert.object(sendFrame);
	assert.arrayOfString(respTypes);
	assert.number(timeout);
	assert.func(cb);

	var self = this;
	var timeoutId;

	var req = new EventEmitter();
	req.retries = 1;

	req.on('send', function (s) {
		s.write(sendFrame);
		timeoutId = setTimeout(function () {
			if (!timeoutId)
				return;
			req.emit('error', new Error('Timeout waiting for ' +
			    'response from SSH agent (' + timeout + ' ms)'));
			self.finishRequest(req);
		}, timeout);
	});

	req.on('error', function (err) {
		if (timeoutId) {
			clearTimeout(timeoutId);
			timeoutId = undefined;
		}

		self.finishRequest(req);

		if (req.retries > 0) {
			req.retries--;
			self.startRequest(req);
			return;
		}

		cb(err);
	});

	req.on('frame', function (frame) {
		if (timeoutId) {
			clearTimeout(timeoutId);
			timeoutId = undefined;
		}

		if (respTypes.indexOf(frame.type) === -1) {
			self.disconnect();
			cb(new AgentProtocolError(frame, 'Frame received ' +
			    'from agent out of order. Got a ' + frame.type +
			    ', expected a ' + respTypes.join(' or ')));
			return;
		}

		self.finishRequest(req);
		cb(null, frame);
	});

	this.startRequest(req);
};

AgentClient.prototype.connect = function (cb) {
	assert.optionalFunc(cb, 'callback');

	var self = this;

	if (this.state === 'connected') {
		if (!this.request && this.requestQueue.length > 0) {
			this.request = this.requestQueue.shift();
			this.request.emit('send', this.encodeStream);
		}
		if (cb)
			cb(null);
		return;
	} else if (this.state === 'connecting') {
		if (cb)
			this.on('connect', cb);
		return;
	}
	assert.strictEqual(this.state, 'disconnected');

	this.state = 'connecting';
	if (cb)
		this.on('connect', cb);

	this.socket = net.connect(this.sockPath);

	this.decodeStream = new AgentDecodeStream({role: 'client'});
	this.socket.pipe(this.decodeStream);

	this.encodeStream = new AgentEncodeStream({role: 'client'});
	this.encodeStream.pipe(this.socket);

	this.socket.on('connect', function () {
		self.state = 'connected';
		if (self.requestQueue.length > 0) {
			self.request = self.requestQueue.shift();
			self.request.emit('send', self.encodeStream);
		}
		self.emit('connect');
	});
	this.socket.on('error', function (err) {
		if (self.request)
			self.request.emit('error', err);
		else
			self.emit('error', err);

		/* socket error will also emit 'close' */
	});
	this.socket.on('close', function () {
		if (self.state === 'connected')
			self.disconnect();
	});

	this.decodeStream.on('readable', function () {
		var frame;
		while ((frame = self.decodeStream.read())) {
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
	this.decodeStream.on('error', function (err) {
		if (self.request)
			self.request.emit('error', err);
		else
			self.emit('error', err);
		self.disconnect();
	});
	this.encodeStream.on('error', function (err) {
		assert.object(self.request);
		self.request.retries = 0;
		self.request.emit('error', err);
		self.disconnect();
	});
};

AgentClient.prototype.disconnect = function (cb) {
	assert.optionalFunc(cb, 'callback');
	assert.strictEqual(this.state, 'connected', 'client must be connected');

	delete (this.request);

	this.socket.destroy();
	this.state = 'disconnected';
	delete (this.socket);
	delete (this.decodeStream);
	delete (this.encodeStream);
	this.emit('disconnect');

	if (this.requestQueue.length > 0)
		this.connect();
};

AgentClient.prototype.startRequest = function (req) {
	assert.object(req);
	assert.ok(req instanceof EventEmitter);
	this.requestQueue.push(req);
	this.connect();
};

AgentClient.prototype.finishRequest = function () {
	assert.object(this.request);
	delete (this.request);
	this.connect();
};

module.exports = AgentClient;
