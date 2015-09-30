sshpk-agent
===========

A library for using the `ssh-agent` protocol, written to leverage the modern
node Streams API and use `sshpk` objects. Supports most client operations
(including key add/remove), but agent support is coming. Re-uses socket
connections where possible for lower latency operation.

Install
-------

```
npm install sshpk-agent
```

Examples
--------

```js
var agent = require('sshpk-agent');
var sshpk = require('sshpk');

var client = new agent.Client();

/* Add a new key to the agent */
var pk = sshpk.parsePrivateKey(fs.readFileSync('id_rsa'), 'pem');
client.addKey(pk, function (err) {
  ...
});

/* List all the keys stored in the agent */
var key;
client.listKeys(function (err, keys) {
  if (err)
    return;
  /* keys is an array of sshpk.Key objects */
  key = keys[0];
});

/* Sign some data with a key */
var data = 'foobar';
client.sign(key, data, function (err, signature) {
  /* signature is an sshpk.Signature object */
  ...
  /* to find out what hash algorithm the agent used -- it chooses for you */
  var algo = signature.hashAlgorithm;
  ...
});
```

Usage
-----

### `new Client([options]);`

Creates a new ssh-agent client.

Parameters

- `options` -- optional Object, containing properties:
  - `socketPath` -- an optional String, path to the UNIX socket to reach the SSH
                    agent via. If not specified, defaults to
                    `process.env['SSH_AUTH_SOCK']`
  - `timeout` -- an optional Number, milliseconds to wait for the agent to
                 respond to a request before returning error. Defaults to 2000.

### `Client#listKeys([options, ]callback);`

Retrieves a list of all keys stored in the agent.

Parameters

- `options` -- optional Object, containg properties:
  - `timeout` -- an optional Number, overrides the constructor timeout just for
                 this request
- `callback` -- function `(error, keys)` with arguments:
  - `error` -- null if no error, otherwise an instance of `Error` or its
               subclasses
  - `keys` -- Array of `sshpk.Key` objects, the available public keys

### `Client#sign(key, data[, options], callback);`

Uses a key stored in the agent to sign some data.

Parameters

- `key` -- an Object, instance of `sshpk.Key`, key to sign with
- `data` -- a Buffer or String, data to be signed
- `options` -- optional Object, containing properties:
  - `timeout` -- an optional Number, overrides the constructor timeout just for
                 this request
- `callback` -- function `(error, signature)` with arguments:
  - `error` -- null if no error, otherwise instance of `Error`
  - `signature` -- an Object, instance of `sshpk.Signature`

### `Client#addKey(privkey[, options], callback);`

Adds a new private key to the agent.

Parameters

- `privkey` -- an Object, instance of `sshpk.PrivateKey`, key to add
- `options` -- optional Object, containing properties:
  - `expires` -- optional Number, seconds until this key expires. If not given,
                 key will last indefinitely. Expiry is handled by the agent
                 itself.
  - `timeout` -- optional Number, overrides the constructor timeout
- `callback` -- function `(error)` with arguments:
  - `error` -- null if no error, otherwise instance of `Error`

### `Client#removeKey(key[, options], callback);`

Removes a private key from the agent.

Parameters

- `key` -- an Object, instance of `sshpk.Key`, key to remove
- `options` -- optional Object, containing properties:
  - `timeout` -- an optional Number, overrides the constructor timeout just for
                 this request
- `callback` -- function `(error)` with arguments:
  - `error` -- null if no error, otherwise instance of `Error`

### `Client#removeAllKeys([options, ]callback);`

Removes all private keys from the agent.

Parameters

- `options` -- optional Object, containing properties:
  - `timeout` -- an optional Number, overrides the constructor timeout just for
                 this request
- `callback` -- function `(error)` with arguments:
  - `error` -- null if no error, otherwise instance of `Error`

### `Client#lock(password[, options], callback);`

Locks the agent with a password, causing it to respond with failure to all
requests (except a request to list keys, which always returns an empty list),
until unlocked with the same password.

Parameters

- `password` -- a String, password to be required to unlock the agent
- `options` -- optional Object, containing properties:
  - `timeout` -- an optional Number, overrides the constructor timeout just for
                 this request
- `callback` -- function `(error)` with arguments:
  - `error` -- null if no error, otherwise instance of `Error`

### `Client#unlock(password[, options], callback);`

Unlocks an agent that has been previously locked. The given `password` must
match the password used to lock the agent.

Parameters

- `password` -- a String, password to unlock the agent
- `options` -- optional Object, containing properties:
  - `timeout` -- an optional Number, overrides the constructor timeout just for
                 this request
- `callback` -- function `(error)` with arguments:
  - `error` -- null if no error, otherwise instance of `Error`
