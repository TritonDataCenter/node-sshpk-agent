/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2021 Joyent, Inc.
 */

var spawn = require('child_process').spawn;
var exec = require('child_process').exec;
var util = require('util');
var EventEmitter = require('events').EventEmitter;
var assert = require('assert-plus');
var fs = require('fs');

var ENV_RE = /([A-Z][A-Z0-9_a-z]+)=([^;]+)(;|$)/g;
var PID_RE = /^echo Agent pid ([0-9]+);/;

function Agent(opts) {
    if (opts === undefined)
        opts = {};
    assert.object(opts, 'options');
    this.open();
}
util.inherits(Agent, EventEmitter);

function SSHVersion(maj, min, patch) {
    this.major = maj;
    this.minor = min;
    this.patch = patch;
}
SSHVersion.prototype.gte = function (maj, min, patch) {
    var v;
    if (maj instanceof SSHVersion)
        v = maj;
    else
        v = new SSHVersion(maj, min, patch);

    return (this.major > v.major ||
        (this.major == v.major && (this.minor > v.minor ||
        (this.minor == v.minor && this.patch >= v.patch))));
};
SSHVersion.prototype.zero = function () {
    return (this.major == 0 && this.minor == 0 && this.patch == 0);
};
SSHVersion.prototype.toString = function () {
    return (this.major + '.' + this.minor + 'p' + this.patch);
};

Agent.getVersion = function (cb) {
    exec('ssh -V', function(err, stdout, stderr) {
        var out = stderr;
        if (Buffer.isBuffer(out))
            out = out.toString('ascii');
        var m = out.trim().match(/^OpenSSH_([0-9]+)\.([0-9]+)p([0-9]+)[, ]|$/);
        if (!m) {
            console.error('ssh -V: %s', out);
            return (cb({error: err, out: out, err: stderr},
                new SSHVersion(0, 0, 0)));
        }
        return (cb(null, new SSHVersion(parseInt(m[1], 10), parseInt(m[2], 10),
            parseInt(m[3], 10))));
    });
};

Agent.prototype.open = function () {
    assert.strictEqual(this.state, undefined, 'agent already opened');
    this.state = 'opening';

    var self = this;
    var env = this.env = {};
    var buf = '';
    var errBuf = '';
    var kid = spawn('ssh-agent', ['-s']);
    kid.stderr.on('data', function (chunk) {
        errBuf += chunk.toString('ascii');
    });
    kid.stderr.pipe(process.stderr);
    kid.stdout.on('data', function (chunk) {
        buf += chunk.toString('ascii');
        var lines = buf.split('\n');
        if (lines.length > 1) {
            lines.slice(0, -1).forEach(function (line) {
                var m, re = new RegExp(ENV_RE);
                while ((m = re.exec(line)) !== null) {
                    env[m[1]] = m[2];
                }
            });
        }
    });
    kid.on('close', function (rc) {
        if (rc === 0 && Object.keys(env).length > 0) {
            self.state = 'running';
            self.emit('open');
        } else {
            self.state = 'closed';
            if (!self.lastError)
                self.lastError = new Error('Agent exited with code ' + rc +
                    ': ' + errBuf.trim());
            self.emit('error', self.lastError);
            self.emit('close');
        }
    });
    setTimeout(function () {
        if (self.state === 'opening') {
            self.lastError = new Error('Timed out waiting for ' +
                'agent to start up, stderr: ' + errBuf.trim());
            kid.kill('SIGINT');
        }
    }, 1000);
};

Agent.prototype.checkRunning = function (cb) {
    assert.optionalFunc(cb, 'callback');
    var self = this;
    var kid = spawn('ps', ['-p', this.env['SSH_AGENT_PID']]);
    kid.on('close', function (rc) {
        if (rc === 0) {
            if (self.state !== 'running') {
                self.state = 'running';
                self.emit('open');
            }
            if (cb)
                cb(true);
        } else {
            if (self.state !== 'closed') {
                self.state = 'closed';
                self.emit('close');
            }
            if (cb)
                cb(false);
        }
    });
}

Agent.prototype.close = function (cb) {
    assert.optionalFunc(cb, 'callback');
    assert.strictEqual(this.state, 'running', 'agent is not running');
    assert.string(this.env['SSH_AGENT_PID'], 'SSH_AGENT_PID');
    var self = this;
    this.state = 'closing';
    var kid = spawn('kill', [this.env['SSH_AGENT_PID']]);
    kid.on('close', function (rc) {
        if (rc != 0)
            self.emit('error', new Error('Failed to kill agent: rc = ' + rc));
        waitUntilDead();
    });
    function waitUntilDead() {
        self.checkRunning(function (running) {
            if (!running) {
                if (cb)
                    cb(null);
            } else {
                setTimeout(waitUntilDead, 100);
            }
        });
    }
};

Agent.prototype.signal = function (signal, cb) {
    assert.optionalFunc(cb, 'callback');
    assert.strictEqual(this.state, 'running', 'agent is not running');
    assert.string(this.env['SSH_AGENT_PID'], 'SSH_AGENT_PID');
    var self = this;
    var kid = spawn('kill', [
        '-' + signal.toUpperCase(),
        this.env['SSH_AGENT_PID']]);
    kid.on('close', function (rc) {
        if (rc != 0) {
            cb(new Error('Failed to kill agent: rc = ' + rc));
            return;
        }
        cb(null);
    });
};

Agent.prototype.importEnv = function () {
    assert.strictEqual(this.state, 'running', 'agent is not running');
    var env = this.env;
    Object.keys(env).forEach(function (k) {
        process.env[k] = env[k];
    });
};

Agent.prototype.childEnv = function () {
    var env = {};
    var myEnv = this.env;
    Object.keys(process.env).forEach(function (k) {
        env[k] = process.env[k];
    });
    Object.keys(myEnv).forEach(function (k) {
        env[k] = myEnv[k];
    });
    return (env);
};

Agent.prototype.deleteKeys = function (cb) {
    assert.func(cb, 'callback');
    assert.strictEqual(this.state, 'running', 'agent is not running');
    var kid = spawn('ssh-add', ['-D'], {env: this.childEnv()});
    var errBuf = '';
    kid.stderr.on('data', function (chunk) {
        errBuf += chunk.toString('ascii');
    });
    kid.on('close', function (rc) {
        if (rc != 0) {
            var err = errBuf.split('\n')[0];
            cb(new Error('ssh-add exited with ' + rc + ': ' + err));
            return;
        }
        cb(null);
    });
};

Agent.prototype.addKey = function (path, cb) {
    assert.func(cb, 'callback');
    assert.strictEqual(this.state, 'running', 'agent is not running');
    fs.chmodSync(path, 0600);
    var kid = spawn('ssh-add', [path], {env: this.childEnv()});
    var errBuf = '';
    kid.stderr.on('data', function (chunk) {
        errBuf += chunk.toString('ascii');
    });
    kid.on('close', function (rc) {
        if (rc != 0) {
            var err = errBuf.split('\n')[0];
            cb(new Error('ssh-add exited with ' + rc + ': ' + err));
            return;
        }
        cb(null);
    })
};

module.exports = Agent;
