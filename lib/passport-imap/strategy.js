/**
 * Module dependencies.
 */
var passport = require('passport')
  , util = require('util')
  , BadRequestError = require('./errors/badrequesterror')
  , Imap = require('imap');

/*
 *The imap authentication strategy authenticates users using imap login information. The strategy requires some options like
 *imaphost name, port and tls which set in req.body
 */

function Strategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }
  if (!verify) throw new Error('local authentication strategy requires a verify function'); 
  passport.Strategy.call(this);
  this.name = 'custom';
  this._verify = verify;
  this._passReqToCallback = options.passReqToCallback;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a form submission.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
  options = options || {};
  var payload = req.body;
  if (!payload.username || !payload.password) {
    return this.fail(new BadRequestError(options.badRequestMessage || 'Missing credentials'));
  }

  var self = this;
  function verified(err, user, info) {
    if (err) { return self.error(err); }
    if (!user) { return self.fail(info); }
    self.success(user, info);
  }
  var tls;
  if (payload.tls) { tls = (payload.tls !== 'false'); } else {tls = true}
  var imap = new Imap({
    user: payload.username,
    password: payload.password,
    host: payload.host,
    port: payload.port||993,
    tls: tls,
    tlsOptions: { rejectUnauthorized: false }
  });
  imap.once('ready', function(){
      var provider = tls+":"+payload.host+":"+payload.port;
      var options = {
        email: payload.username,
        password: payload.password,
        provider: provider
      };
    if (typeof self._verify == "function") {
      self._verify(options, verified);
    } else {
      console.log("Success fallback is required to generate the user!");
      return self.fail("Success fallback is required to generate the user!");
    }
  });
  imap.connect();
  imap.once('error', function(err) {
    return self.fail("Invalid credantials");
  });
}

/**
 * Expose `Strategy`.
 */ 
module.exports = Strategy;
