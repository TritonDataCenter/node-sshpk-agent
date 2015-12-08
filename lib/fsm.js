// Copyright 2015 Joyent, Inc.

module.exports = FSM;

var assert = require('assert-plus');
var util = require('util');
var EventEmitter = require('events').EventEmitter;

function FSM(defState) {
	assert.string(defState, 'default state');
	this.fsm_stListeners = [];
	this.fsm_stTimers = [];
	EventEmitter.call(this);
	this.gotoState(defState);
}
util.inherits(FSM, EventEmitter);
FSM.prototype.getState = function () {
	return (this.fsm_state);
};
FSM.prototype.onState = function (state, cb) {
	assert.string(state, 'state');
	assert.func(cb, 'callback');
	if (this.fsm_state === state ||
	    this.fsm_state.indexOf(state + '.') === 0) {
		cb();
		return;
	}
	var self = this;
	function stateCb(newState) {
		if (newState !== state &&
		    newState.indexOf(state + '.') !== 0) {
			self.once('stateChanged', stateCb);
			return;
		}
		cb();
	}
	self.once('stateChanged', stateCb);
};
FSM.prototype.sOnState = function (obj, state, cb) {
	assert.string(state, 'state');
	assert.func(cb, 'callback');
	if (obj.fsm_state === state ||
	    obj.fsm_state.indexOf(state + '.') === 0) {
		cb();
		return;
	}
	var self = this;
	function stateCb(newState) {
		if (newState !== state &&
		    newState.indexOf(state + '.') !== 0) {
			self.sOnce(obj, 'stateChanged', stateCb);
			return;
		}
		cb();
	}
	this.sOnce(obj, 'stateChanged', stateCb);
};
FSM.prototype.gotoState = function (state) {
	assert.string(state, 'state');

	/*
	 * If we're changing to a state that is not a sub-state of this one,
	 * then kill of all timers and listeners we created in this state.
	 */
	var parts = (this.fsm_state ? this.fsm_state.split('.') : ['']);
	var newParts = state.split('.');
	if (parts[0] !== newParts[0]) {
		var ls = this.fsm_stListeners;
		for (var i = 0; i < ls.length; ++i) {
			ls[i][0].removeListener(ls[i][1], ls[i][2]);
		}
		var ts = this.fsm_stTimers;
		for (i = 0; i < ts.length; ++i) {
			clearTimeout(ts[i]);
		}
		this.fsm_stTimers = [];
		this.fsm_stListeners = [];
	}

	var f = this['state_' + newParts[0]];
	if (typeof (f) !== 'function')
		throw (new Error('Unknown FSM state: ' + state));
	if (newParts[1] !== undefined) {
		f = f[newParts[1]];
		if (typeof (f) !== 'function')
			throw (new Error('Unknown FSM sub-state: ' + state));
	}
	this.fsm_state = state;
	f.call(this, this.sOn.bind(this), this.sOnce.bind(this),
	    this.sTimeout.bind(this), this.sOnState.bind(this));

	this.emit('stateChanged', state);
};
FSM.prototype.sOn = function (obj, evt, cb) {
	obj.on(evt, cb);
	this.fsm_stListeners.push([obj, evt, cb]);
};
FSM.prototype.sOnce = function (obj, evt, cb) {
	obj.once(evt, cb);
	this.fsm_stListeners.push([obj, evt, cb]);
};
FSM.prototype.sTimeout = function (timeout, cb) {
	var timer = setTimeout(cb, timeout);
	this.fsm_stTimers.push(timer);
};
