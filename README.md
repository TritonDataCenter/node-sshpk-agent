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

TODO.

Usage
-----

### `new AgentClient([options]);`

Creates a new ssh-agent client.

Parameters

- `options` -- optional Object, containing properties:
  - `socketPath` -- an optional String, path to the UNIX socket to reach the SSH
                    agent via. If not specified, defaults to
                    `process.env['SSH_AUTH_SOCK']`
  - `timeout` -- an optional Number, milliseconds to wait for the agent to
                 respond to a request before returning error. Defaults to 2000.

### `AgentClient#listKeys([options, ]callback);`

Retrieves a list of all keys stored in the agent.

Parameters

- `options` -- optional Object, containg properties:
  - `timeout` -- an optional Number, overrides the constructor timeout just for
                 this request
- `callback` -- function `(error, keys)` with arguments:
  - `error` -- null if no error, otherwise an instance of `Error` or its
               subclasses
  - `keys` -- Array of `sshpk.Key` objects, the available public keys

### `AgentClient#sign(key, data[, options], callback);`

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
