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

### `Client#listCertificates([options, ]callback);`

Retrieves a list of all certificates stored in the agent.

Parameters

- `options` -- optional Object, containg properties:
  - `timeout` -- an optional Number, overrides the constructor timeout just for
                 this request
- `callback` -- function `(error, keys)` with arguments:
  - `error` -- null if no error, otherwise an instance of `Error` or its
               subclasses
  - `keys` -- Array of `sshpk.Certificate` objects, the available certificates

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

### `Client#createSelfSignedCertificate(subject, key, options, cb)`

Uses a key stored in the agent to create a self-signed certificate for that
key. The certificate can be read back in both OpenSSH and X.509 formats.

Parameters

 - `subject` -- an Identity, the subject of the certificate
 - `key` -- an Object, instance of `sshpk.Key`, key to sign with and the
   subject key
 - `options` -- an Object, additional options, with keys:
   - `lifetime` -- optional Number, lifetime of the certificate from now in
     seconds
   - `validFrom`, `validUntil` -- optional Dates, beginning and end of
     certificate validity period. If given, `lifetime` will be ignored.
   - `serial` -- optional Buffer, the serial number of the certificate
   - `purposes` -- optional Array of String, X.509 key usage restrictions
 - `callback` -- function `(error, certificate)`, with arguments:
   - `error` -- null if no error, otherwise instance of `Error`
   - `certificate` -- an Object, instance of `sshpk.Certificate`

### `Client#createCertificate(subject, subjectKey, issuer, key, options, cb)`

Uses a key stored in the agent to create and sign a certificate for some other
key (not necessarily in the agent). The certificate can be read back in both
OpenSSH and X.509 formats.

Parameters

 - `subject` -- an Identity, the subject of the certificate
 - `subjectKey` -- an Object, instance of `sshpk.Key`, key of the subject
   entity (does not have to reside in the agent)
 - `issuer` -- an Identity, the issuer of the certificate
 - `key` -- an Object, instance of `sshpk.Key`, key to sign with (must be in
   the agent, and match up with the `issuer` identity)
 - `options` -- an Object, additional options, with keys:
   - `lifetime` -- optional Number, lifetime of the certificate from now in
     seconds
   - `validFrom`, `validUntil` -- optional Dates, beginning and end of
     certificate validity period. If given, `lifetime` will be ignored.
   - `serial` -- optional Buffer, the serial number of the certificate
   - `purposes` -- optional Array of String, X.509 key usage restrictions
 - `callback` -- function `(error, certificate)`, with arguments:
   - `error` -- null if no error, otherwise instance of `Error`
   - `certificate` -- an Object, instance of `sshpk.Certificate`

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

### `Client#addCertificate(cert, privkey[, options], callback);`

Adds a new certificate and private key pair to the agent.

Parameters

- `cert` -- an Object, instance of `sshpk.Certificate`, cert to add
- `privkey` -- an Object, instance of `sshpk.PrivateKey`, subject private key
               of the certificate
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

### `Client#listExtensions(callback);`

Requests the "query" extension (see draft-miller-ssh-agent-00) from the agent
to list what agent protocol extensions are supported. These are returned as
a list of Strings.

Parameters

 - `callback` -- function `(error, extensions)` with arguments:
  - `error` -- null if no error, otherwise instance of `Error`
  - `extensions` -- Array of String, supported extensions
