// Copyright 2015 Joyent, Inc.

var assert = require('assert-plus');
var util = require('util');
var sshpk = require('sshpk');

var LenPrefixBuf = {
	encodeSize: function (v) {
		assert.buffer(v);
		return (4 + v.length);
	},
	encode: function (v, buf, offset) {
		assert.buffer(v);
		buf.writeUInt32BE(v.length, offset);
		offset += 4;
		v.copy(buf, offset);
		offset += v.length;
		return (offset);
	},
	decodeSize: function (buf, offset) {
		return (4 + buf.readUInt32BE(offset));
	},
	decode: function (buf, offset) {
		var len = buf.readUInt32BE(offset);
		offset += 4;
		var v = buf.slice(offset, offset + len);
		offset += len;
		return ({value: v, offset: offset});
	}
};

var SSHString = {
	encodeSize: function (v) {
		assert.string(v);
		return (4 + v.length);
	},
	encode: function (v, buf, offset) {
		return (LenPrefixBuf.encode(new Buffer(v), buf, offset));
	},
	decodeSize: LenPrefixBuf.decodeSize,
	decode: function (buf, offset) {
		var r = LenPrefixBuf.decode(buf, offset);
		r.value = r.value.toString('utf-8');
		return (r);
	}
};

var U32 = {
	encodeSize: function (v) { return (4); },
	encode: function (v, buf, offset) {
		assert.number(v);
		buf.writeUInt32BE(v, offset);
		return (offset + 4);
	},
	decodeSize: function (buf, offset) { return (4); },
	decode: function (buf, offset) {
		var v = buf.readUInt32BE(offset);
		return ({value: v, offset: offset + 4});
	}
};

var SignReqFlags = {
	encodeSize: U32.encodeSize,
	encode: function (v, buf, offset) {
		assert.arrayOfString(v, 'flags');
		var x = 0x0;
		if (v.indexOf('old-signature') !== -1)
			x |= 0x01;
		return (U32.encode(x, buf, offset));
	},
	decodeSize: U32.decodeSize,
	decode: function (buf, offset) {
		var r = U32.decode(buf, offset);
		var v = [];
		if ((r.value & 0x01) === 0x01)
			v.push('old-signature');
		r.value = v;
		return (r);
	}
};

var PublicKey = {
	encodeSize: function (v) {
		assert.object(v);
		assert.buffer(v.key, 'key');
		assert.string(v.comment, 'comment');
		return (4 + v.key.length + 4 + v.comment.length);
	},
	encode: function (v, buf, offset) {
		assert.object(v);
		assert.buffer(v.key, 'key');
		assert.string(v.comment, 'comment');

		offset = LenPrefixBuf.encode(v.key, buf, offset);
		offset = SSHString.encode(v.comment, buf, offset);
		return (offset);
	},
	decodeSize: function (buf, offset) {
		var start = offset;
		var keyLen = buf.readUInt32BE(offset);
		offset += 4 + keyLen;
		var commentLen = buf.readUInt32BE(offset);
		offset += 4 + commentLen;
		return (offset - start);
	},
	decode: function (buf, offset) {
		var v = {};
		var r = LenPrefixBuf.decode(buf, offset);
		v.key = r.value;
		r = SSHString.decode(buf, r.offset);
		v.comment = r.value;
		r.value = v;
		return (r);
	}
};

var Identities = {
	encodeSize: function (v) {
		assert.arrayOfObject(v);
		var len = 4;
		v.forEach(function (key) {
			len += PublicKey.encodeSize(key);
		});
		return (len);
	},
	encode: function (v, buf, offset) {
		assert.arrayOfObject(v);
		buf.writeUInt32BE(v.length, offset);
		offset += 4;
		for (var i = 0; i < v.length; ++i)
			offset = PublicKey.encode(v[i], buf, offset);
		return (offset);
	},
	decodeSize: function (buf, offset) {
		var start = offset;
		var count = buf.readUInt32BE(offset);
		offset += 4;
		for (var i = 0; i < count; ++i)
			offset += PublicKey.decodeSize(buf, offset);
		return (offset - start);
	},
	decode: function (buf, offset) {
		var v = [];
		var count = buf.readUInt32BE(offset);
		offset += 4;
		for (var i = 0; i < count; ++i) {
			var r = PublicKey.decode(buf, offset);
			v.push(r.value);
			offset = r.offset;
		}
		return ({value: v, offset: offset});
	}
};

var PrivateKey = {
	encodeSize: function (v) {
		assert.buffer(v);
		return (v.length);
	},
	encode: function (v, buf, offset) {
		assert.buffer(v);
		v.copy(buf, offset);
		return (offset + v.length);
	},
	decodeSize: function (buf, offset) {
		var keyBuf = buf.slice(offset);
		var ret = {};
		try {
			sshpk.PrivateKey.formats.rfc4253.
			    readInternal(ret, 'private', keyBuf);
			return (ret.consumed);
		} catch (e) {
			sshpk.Certificate.formats.openssh.fromBuffer(
			    keyBuf, undefined, ret);
			return (ret.consumed);
		}
	},
	decode: function (buf, offset) {
		var size = PrivateKey.decodeSize(buf, offset);
		var v = buf.slice(offset, offset + size);
		return ({value: v, offset: offset + size});
	}
};

var KeyConstraints = {
	encodeSize: function (v) {
		assert.arrayOfObject(v);
		var sz = 0;
		v.forEach(function (c) {
			switch (c.type) {
			case 'lifetime':
				sz += 1 + U32.encodeSize();
				break;
			case 'confirm':
				sz += 1;
				break;
			default:
				assert.fail('unknown constraint type: ' +
				    c.type);
				break;
			}
		});
		return (sz);
	},
	encode: function (v, buf, offset) {
		assert.arrayOfObject(v);
		v.forEach(function (c) {
			switch (c.type) {
			case 'lifetime':
				buf[offset++] = 1;
				offset = U32.encode(c.seconds, buf, offset);
				break;
			case 'confirm':
				buf[offset++] = 2;
				break;
			default:
				assert.fail('unknown constraint type: ' +
				    c.type);
				break;
			}
		});
		return (offset);
	},
	decodeSize: function (buf, offset) {
		var start = offset;
		while (offset < buf.length) {
			var type = buf[offset];
			switch (type) {
			case 1:
				offset += 5;
				break;
			case 2:
				offset++;
				break;
			default:
				return (offset - start);
			}
		}
		return (offset - start);
	},
	decode: function (buf, offset) {
		var v = [];
		while (offset < buf.length) {
			var type = buf[offset];
			switch (type) {
			case 1:
				offset++;
				var r = U32.decode(buf, offset);
				v.push({type: 'lifetime', seconds: r.value});
				offset = r.offset;
				break;
			case 2:
				offset++;
				v.push({type: 'confirm'});
				break;
			default:
				return ({value: v, offset: offset});
			}
		}
		return ({value: v, offset: offset});
	}
};

var agentFrames = {
	'request-identities': {
		id: 11,
		args: []
	},
	'sign-request': {
		id: 13,
		args: [
			{type: LenPrefixBuf, name: 'publicKey'},
			{type: LenPrefixBuf, name: 'data'},
			{type: SignReqFlags, name: 'flags'}
		]
	},
	'add-identity': {
		id: 17,
		args: [
			{type: PrivateKey, name: 'privateKey'},
			{type: SSHString, name: 'comment'}
		]
	},
	'remove-identity': {
		id: 18,
		args: [
			{type: LenPrefixBuf, name: 'publicKey'}
		]
	},
	'remove-all-identities': {
		id: 19,
		args: []
	},
	'lock': {
		id: 22,
		args: [
			{type: SSHString, name: 'password'}
		]
	},
	'unlock': {
		id: 23,
		args: [
			{type: SSHString, name: 'password'}
		]
	},
	'add-identity-constrained': {
		id: 25,
		args: [
			{type: PrivateKey, name: 'privateKey'},
			{type: SSHString, name: 'comment'},
			{type: KeyConstraints, name: 'constraints'}
		]
	}
};

/* Add lookup by ID */
Object.keys(agentFrames).forEach(function (k) {
	var f = agentFrames[k];
	f.name = k;
	agentFrames[f.id] = f;
});

var clientFrames = {
	'success': {
		id: 6,
		args: []
	},
	'failure': {
		id: 5,
		args: []
	},
	'identities-answer': {
		id: 12,
		args: [
			{type: Identities, name: 'identities'}
		]
	},
	'sign-response': {
		id: 14,
		args: [
			{type: LenPrefixBuf, name: 'signature'}
		]
	}
};

/* Add lookup by ID */
Object.keys(clientFrames).forEach(function (k) {
	var f = clientFrames[k];
	f.name = k;
	clientFrames[f.id] = f;
});

module.exports = {
	agentFrames: agentFrames,
	clientFrames: clientFrames
};
