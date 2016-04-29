// Copyright 2015 Joyent, Inc.

var assert = require('assert-plus');
var util = require('util');
var stream = require('stream');

var protocol = require('./protocol');
var errs = require('./errors');
var AgentProtocolError = errs.AgentProtocolError;

function AgentEncodeStream(opts) {
	assert.object(opts, 'options');
	assert.string(opts.role, 'options.role');
	this.role = opts.role.toLowerCase();
	switch (this.role) {
	case 'agent':
		this.frameDefs = protocol.clientFrames;
		break;
	case 'client':
		this.frameDefs = protocol.agentFrames;
		break;
	default:
		/* assert below will fail */
		break;
	}
	assert.object(this.frameDefs, 'frame defs for role ' + this.role);

	opts.readableObjectMode = false;
	opts.writableObjectMode = true;
	stream.Transform.call(this, opts);
}
util.inherits(AgentEncodeStream, stream.Transform);

AgentEncodeStream.prototype._transform = function (obj, enc, cb) {
	assert.object(obj);
	var err, i;

	var def = this.frameDefs[obj.type.toLowerCase()];
	if (def === undefined) {
		err = new AgentProtocolError(obj, 'unknown frame type: ' +
		    obj.type);
		cb(err);
		return;
	}

	/* length prefix + frame id */
	var len = 4 + 1;
	var argdef, v;
	for (i = 0; i < def.args.length; ++i) {
		argdef = def.args[i];
		v = obj[argdef.name];
		if (v === undefined) {
			err = new AgentProtocolError(obj, 'missing ' +
			    'argument to ' + def.name + ': ' + argdef.name);
			cb(err);
			return;
		}

		try {
			len += argdef.type.encodeSize(v);
		} catch (e) {
			err = new AgentProtocolError(obj, 'argument ' +
			    argdef.name + ' to ' + def.name + ' is invalid: ' +
			    e.message);
			cb(err);
			return;
		}
	}

	var frame = new Buffer(len);
	var offset = 0;

	frame.writeUInt32BE(len - 4, 0);
	offset += 4;
	frame[offset++] = def.id;

	for (i = 0; i < def.args.length; ++i) {
		argdef = def.args[i];
		v = obj[argdef.name];

		try {
			offset = argdef.type.encode(v, frame, offset);
		} catch (e) {
			err = new AgentProtocolError(obj, 'argument ' +
			    argdef.name + ' to ' + def.name + ' is invalid: ' +
			    e.message);
			cb(err);
			return;
		}
	}

	if (offset !== frame.length) {
		err = new AgentProtocolError(obj, 'arguments to ' +
		    def.name + ' smaller than expected: ' + offset + ' bytes ' +
		    ' vs ' + frame.length + ' bytes');
		cb(err);
		return;
	}

	this.push(frame);
	cb();
};

AgentEncodeStream.prototype._flush = function (cb) {
	cb();
};


function AgentDecodeStream(opts) {
	assert.object(opts, 'options');
	assert.string(opts.role, 'options.role');
	this.role = opts.role.toLowerCase();
	this.frameDefs = protocol[this.role + 'Frames'];
	assert.object(this.frameDefs, 'frame defs for role ' + this.role);

	opts.readableObjectMode = true;
	opts.writableObjectMode = false;
	stream.Transform.call(this, opts);

	this.frame = new Buffer(0);
}
util.inherits(AgentDecodeStream, stream.Transform);

AgentDecodeStream.prototype._transform = function (chunk, enc, cb) {
	this.frame = Buffer.concat([this.frame, chunk]);

	while (this.frame.length >= 4) {
		var len = this.frame.readUInt32BE(0);
		var err;

		if (this.frame.length < (len + 4)) {
			/*
			 * Keep it buffered up, see if we get the rest of
			 * it next time around
			 */
			break;

		} else {
			/* We have an entire frame, let's process it */
			var frame = this.frame.slice(4, len + 4);
			this.frame = this.frame.slice(len + 4);

			var offset = 0;
			var id = frame[offset++];
			var def = this.frameDefs[id];
			var argdef;

			if (def === undefined) {
				err = new AgentProtocolError(frame,
				    'unknown frame type: ' + id);
				this.emit('error', err);
				cb();
				return;
			}

			var obj = {};
			obj.type = def.name;

			/*
			 * First compute the lengths of arguments and verify
			 * that they are all present in the buffer
			 */
			var argStart = offset;
			for (var i = 0; i < def.args.length; ++i) {
				argdef = def.args[i];
				try {
					var sz = argdef.type.decodeSize(
					    frame, offset);
				} catch (e) {
					err = new AgentProtocolError(frame,
					    'bad argument ' + argdef.name +
					    ' in ' + def.name + ' @' + offset);
					this.emit('error', err);
					cb();
					return;
				}
				if ((offset + sz) > frame.length) {
					err = new AgentProtocolError(frame,
					    'bad length of argument ' +
					    argdef.name + ' in ' + def.name +
					    ': ' + sz);
					this.emit('error', err);
					cb();
					return;
				}
				offset += sz;
			}
			if (offset !== frame.length) {
				err = new AgentProtocolError(frame,
				    'unconsumed bytes after final argument: ' +
				    'offset = ' + offset + ' in ' + def.name);
				this.emit('error', err);
				cb();
				return;
			}

			/* Now parse the actual argument data */
			offset = argStart;
			for (i = 0; i < def.args.length; ++i) {
				argdef = def.args[i];
				try {
					var r = argdef.type.decode(
					    frame, offset);
				} catch (e) {
					err = new AgentProtocolError(frame,
					    'bad argument ' + argdef.name +
					    ' in ' + def.name + ' @' + offset);
					this.emit('error', err);
					cb();
					return;
				}
				offset = r.offset;
				obj[argdef.name] = r.value;
			}

			this.push(obj);

		}
	}
	cb();
};

AgentDecodeStream.prototype._flush = function (cb) {
	if (this.frame.length > 0) {
		var err = new AgentProtocolError(this.frame,
		    'leftover bytes in buffer not used at flush time');
		this.emit('error', err);
		cb();
		return;
	}
	cb();
};


module.exports = {
	AgentDecodeStream: AgentDecodeStream,
	AgentEncodeStream: AgentEncodeStream
};
