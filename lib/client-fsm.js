// Copyright 2015 Joyent, Inc.

module.exports = ClientFSM;

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

var FSM = require('./fsm');

function RequestQueue(client) {
	this.rq_client = client;
	this.rq_recent = [];
	this.rq_queue = [];
	this.rq_request = undefined;
	FSM.call(this, 'idle');
}
util.inherits(RequestQueue, FSM);
RequestQueue.prototype.onStateEntry = function (state) {
	var self = this;
	switch (state) {

	case 'idle':
		/*
		 * Store the last request, if any, for a while, to make
		 * debugging a little easier.
		 */
		if (this.rq_request)
			this.rq_recent.push(this.rq_request);
		if (this.rq_recent.length > 4)
			this.rq_recent.shift();

		/*
		 * Transitions out of the idle state occur when there is a
		 * request on the rq_queue.
		 */
		if (this.rq_queue.length > 0) {
			self.gotoState('connect');
		} else {
			this.rq_client.unref();
			this.sOnce(this, 'nonEmptyAsserted', function () {
				self.gotoState('connect');
			});
		}
		break;

	case 'connect':
		/*
		 * Transition out of the connect state when the client has
		 * been connected successfully.
		 */
		this.sOnState(this.rq_client, 'connected', function () {
			self.gotoState('req');
		});
		this.rq_client.ref();
		this.rq_client.connect();
		break;

	case 'req':
		assert.ok(this.rq_queue.length > 0);
		this.rq_request = this.rq_queue.shift();
		assert.strictEqual(this.rq_request.getState(), 'waiting');

		/* Transition to idle when the request is done. */
		this.sOnState(this.rq_request, 'done', function () {
			self.gotoState('idle');
		});
		this.rq_request.ready();
		break;

	default:
		throw (new Error('Unknown state: ' + this.rq_state));
	}
};
RequestQueue.prototype.push = function (req) {
	assert.ok(req instanceof Request);
	var ret = this.rq_queue.push(req);
	this.emit('nonEmptyAsserted');
	return (ret);
};

function Request(client, sendFrame, respTypes, timeout, cb) {
	assert.ok(client instanceof ClientFSM);
	this.r_client = client;

	assert.object(sendFrame, 'sendFrame');
	this.r_sendFrame = sendFrame;

	assert.arrayOfString(respTypes, 'respTypes');
	this.r_respTypes = respTypes;

	assert.number(timeout, 'timeout');
	this.r_timeout = timeout;

	this.r_error = undefined;
	this.r_reply = undefined;
	this.r_retries = 3;

	assert.func(cb, 'callback');
	this.r_cb = cb;

	FSM.call(this, 'waiting');
}
util.inherits(Request, FSM);
Request.prototype.onStateEntry = function (state) {
	var self = this;
	switch (state) {

	case 'waiting':
		/* Wait for the "ready" signal. */
		this.sOnce(this, 'readyAsserted', function () {
			self.gotoState('sending');
		});
		break;

	case 'sending':
		this.r_error = undefined;
		this.r_reply = undefined;

		/* Transitions out of sending are to either error or done. */

		this.sTimeout(this.r_timeout, function () {
			self.r_error = new Error('Timeout waiting for ' +
			    'response from SSH agent (' + self.r_timeout +
			    ' ms)');
			self.r_client.disconnect();
			self.gotoState('error');
		});

		this.sOnce(this.r_client, 'error', function (err) {
			self.r_error = err;
			self.gotoState('error');
		});

		this.sOnce(this.r_client, 'frame', function (frame) {
			if (self.r_respTypes.indexOf(frame.type) === -1) {
				self.r_error = new AgentProtocolError(frame,
				    'Frame received from agent out of order. ' +
				    'Got a ' + frame.type + ', expected a ' +
				    self.r_respTypes.join(' or '));
				self.gotoState('error');
				return;
			}
			self.r_reply = frame;
			self.gotoState('done');
		});

		this.r_client.sendFrame(this.r_sendFrame);
		break;

	case 'error':
		if (this.r_retries > 0) {
			--this.r_retries;
			this.sOnState(this.r_client, 'connected', function () {
				self.gotoState('sending');
			});
			this.r_client.connect();
		} else {
			this.gotoState('done');
		}
		break;

	case 'done':
		if (this.r_error === undefined) {
			this.r_cb(null, this.r_reply);
		} else {
			this.r_cb(this.r_error);
		}
		break;

	default:
		throw (new Error('Unknown state: ' + this.rq_state));
	}
};
Request.prototype.ready = function () {
	this.emit('readyAsserted');
};

function ClientFSM(opts) {
	if (opts === undefined)
		opts = {};
	assert.object(opts, 'options');
	var sockPath = opts.socketPath;
	if (sockPath === undefined)
		sockPath = process.env['SSH_AUTH_SOCK'];
	assert.string(sockPath, 'options.socketPath or $SSH_AUTH_SOCK');
	assert.optionalNumber(opts.timeout, 'options.timeout');

	this.c_sockPath = sockPath;
	this.c_timeout = opts.timeout || 2000;
	this.c_socket = undefined;
	this.c_encodeStream = undefined;
	this.c_decodeStream = undefined;
	this.c_connectError = undefined;
	this.c_connectRetries = 3;
	this.c_lastError = undefined;
	this.c_ref = false;

	FSM.call(this, 'disconnected');
	this.c_rq = new RequestQueue(this);
}
util.inherits(ClientFSM, FSM);

ClientFSM.prototype.onStateEntry = function (state) {
	var self = this;
	switch (state) {

	case 'disconnected':
		this.sOnce(this, 'connectAsserted', function () {
			self.gotoState('connecting');
		});
		break;

	case 'connecting':
		this.c_socket = net.connect(this.c_sockPath);

		this.sTimeout(this.c_timeout, function () {
			self.c_connectError = new Error('Timed out while ' +
			    'connecting to socket: ' + self.c_sockPath + ' (' +
			    self.c_timeout + ' ms)');
			self.gotoState('connectError');
		});

		var errCb = function (err) {
			self.c_connectError = err;
			self.gotoState('connectError');
		};
		this.sOnce(this.c_socket, 'error', errCb);

		this.sOnce(this.c_socket, 'connect', function () {
			self.gotoState('connected');
		});
		break;

	case 'connectError':
		if (this.c_connectRetries > 0) {
			--this.c_connectRetries;
			this.gotoState('connecting');
		} else {
			this.c_wantConnect = false;
			this.emit('error', this.c_connectError);
			this.gotoState('disconnected');
		}
		break;

	case 'connected':
		this.c_connectRetries = 3;
		this.c_encodeStream = new AgentEncodeStream({role: 'client'});
		this.c_decodeStream = new AgentDecodeStream({role: 'client'});
		this.c_socket.pipe(this.c_decodeStream);
		this.c_encodeStream.pipe(this.c_socket);

		var errHandler = function (err) {
			self.c_lastError = err;
			self.emit('error', err);
			self.gotoState('disconnecting');
		};

		this.sOnce(this.c_socket, 'error', errHandler);
		this.sOnce(this.c_decodeStream, 'error', errHandler);
		this.sOnce(this.c_encodeStream, 'error', errHandler);

		this.sOnce(this.c_socket, 'close', function () {
			if (self.c_ref) {
				console.error(self);
				errHandler(new Error('Unexpectedly lost ' +
				    'connection to SSH agent'));
			} else {
				self.gotoState('disconnecting');
			}
		});

		this.sOn(this.c_decodeStream, 'readable',
		    function () {
			var frame;
			while (self.c_decodeStream &&
			    (frame = self.c_decodeStream.read())) {
				if (self.listeners('frame').length < 1) {
					errHandler(new Error('Unexpected ' +
					    'frame received from SSH agent: ' +
					    frame.type));
					return;
				}
				self.emit('frame', frame);
			}
		});

		this.sOnce(this, 'disconnectAsserted', function () {
			self.gotoState('disconnecting');
		});

		if (this.c_ref)
			self.gotoState('connected.busy');
		else
			self.gotoState('connected.idle');
		break;

	case 'connected.busy':
		if (this.c_socket.ref)
			this.c_socket.ref();
		this.sOnce(this, 'unrefAsserted', function () {
			self.gotoState('connected.idle');
		});
		break;

	case 'connected.idle':
		if (this.c_socket.unref) {
			this.c_socket.unref();
			this.sOnce(this, 'refAsserted', function () {
				self.gotoState('connected.busy');
			});
		} else {
			this.gotoState('disconnecting');
		}
		break;

	case 'disconnecting':
		this.c_socket.destroy();
		this.c_socket = undefined;

		this.c_encodeStream = undefined;
		this.c_decodeStream = undefined;

		this.c_errHandler = undefined;
		this.c_readableHandler = undefined;
		this.c_closeListener = undefined;

		this.gotoState('disconnected');
		break;

	default:
		throw (new Error('Unknown state: ' + this.rq_state));
	}
};

ClientFSM.prototype.ref = function () {
	this.c_ref = true;
	this.emit('refAsserted');
};

ClientFSM.prototype.unref = function () {
	this.c_ref = false;
	this.emit('unrefAsserted');
};

ClientFSM.prototype.disconnect = function () {
	this.emit('disconnectAsserted');
};

ClientFSM.prototype.connect = function (cb) {
	assert.optionalFunc(cb, 'callback');
	if (cb)
		this.onState('connected', cb);
	this.emit('connectAsserted');
};

ClientFSM.prototype.sendFrame = function (frame) {
	assert.ok(this.c_encodeStream);
	this.c_encodeStream.write(frame);
};

ClientFSM.prototype.doRequest = function (frame, resps, timeout, cb) {
	var req = new Request(this, frame, resps,
	    timeout || this.c_timeout, cb);
	this.c_rq.push(req);
};
