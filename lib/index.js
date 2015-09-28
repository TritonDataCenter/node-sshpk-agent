// Copyright 2015 Joyent, Inc.

var AgentClient = require('./agent-client');
var errs = require('./errors');

module.exports = {
	AgentClient: AgentClient,

	AgentProtocolError: errs.AgentProtocolError
};
