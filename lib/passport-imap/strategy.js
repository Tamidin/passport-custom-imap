/**
 * Module dependencies.
 */
var passport = require('passport')
  , util = require('util')
  , BadRequestError = require('./errors/badrequesterror')
  , Imap = require('imap');

/*
 *The imap authentication strategy authenticates users using imap login information. The strategy requires some options like
 *imaphost name, port and tls which set in req.query
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
  if (!req.query.username || !req.query.password) {
    return this.fail(new BadRequestError(options.badRequestMessage || 'Missing credentials'));
  }

  var self = this;
  function verified(err, user, info) {
    console.log(user)
    if (err) { return self.error(err); }
    if (!user) { return self.fail(info); }
    self.success(user, info);
  }

  var imap = new Imap({
    user: req.query.username,
    password: req.query.password,
    host: req.query.host,
    port: req.query.port||993,
    tls: req.query.tls||true,
    tlsOptions: { rejectUnauthorized: false }
  });

  imap.once('ready', function(){
      var user = { id: req.query.username };
    if (typeof self._verify == "function") {
      self._verify(req.query.username, req.query.password, verified);
    } else {
      console.log("Success fallback is required to generate the user!");
      return self.fail("Success fallback is required to generate the user!");
    }
  });
  imap.connect();
  imap.once('error', function(err) {
    console.log(imap);
    return self.fail("Invalid credantials");
  });
}

/**
 * Expose `Strategy`.
 */ 
module.exports = Strategy;
