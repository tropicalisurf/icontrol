var storage = require('node-persist');
var EventEmitter = require('events').EventEmitter;
var inherits = require('util').inherits;
var format = require('util').format;
var debug = require('debug')('iControl');
var WebSocket = require('ws');
var request = require('request').defaults({jar: true/*, proxy:"http://localhost:8888", strictSSL:false*/}); // use cookies

module.exports = {
  iControl: iControl
}

/**
 * iControl represents an iControl-based security system (like Xfinity Home, ADT Pulse), and handles logging in
 * and state changes.
 */

function iControl(config) {
  this.system = config.system;
  this.email = config.email;
  this.password = config.password;
  this.pinCode = config.pinCode;
  
  // interested parties in us being logged in
  this._loginCompleteCallbacks = [];
  this._loggingIn = false;
  
  storage.initSync();

  // try to load the refresh token if we have one stored from a previous session
  var data = storage.getItem("iControl." + this.email + ".json");
  this._refreshToken = data && data.refresh_token;
  this._accessToken = data && data.access_token;
  this._accessTokenExpires = data && data.access_token_expires;
}

inherits(iControl, EventEmitter);

iControl.Systems = {
  XFINITY_HOME: {
    oauthLoginURL: "https://login.comcast.net/oauth/",
    clientID: "Xfinity-Home-iOS-App",
    clientSecret: "77b366f9a135c7ab391044234a26b1d6b1e08f66",
    clientRedirect: "xfinityhome://auth",
    restAPI: "https://xip.comcast.net/xip/oauth-proxy/homestream/rest/"
  }
}

iControl.ArmState = {
  DISARMED: "disarmed",
  ARMED_AWAY: "away",
  ARMED_NIGHT: "night",
  ARMED_STAY: "stay"
}

iControl.prototype.getArmState = function(callback) {
  debug("Requesting current arm state..");
  
  this._makeAuthenticatedRequest({path: "site/:site/device/panel/:panel"}, function(err, panel) {
    if (err) return callback && callback(err);

    var armType = panel.properties.armType; // "away", "night", "stay", or null (disarmed)
    var armState = armType || "disarmed";
    debug("Retrieved current arm state: %s", armState);
    callback(null, armState);
    
  }.bind(this));
}

iControl.prototype.setArmState = function(armState, callback) {
  debug("Setting arm state to %s...", armState);
  
  var endpoint = (armState == "disarmed" ? "disarm" : "arm");
  var form = {
    code: this.pinCode
  }
  
  if (endpoint !== "disarm")
    form.armType = armState;
  
  var req = {
    method: "POST",
    path: "site/:site/device/panel-:panel/" + endpoint,
    form: form
  }
  
  this._makeAuthenticatedRequest(req, function(err, panel) {
    if (err) return callback && callback(err);

    debug("Set current arm state to %s", armState);
    callback(null);
    
  }.bind(this));
}

iControl.prototype.subscribeEvents = function(callback) {
  
  this._makeAuthenticatedRequest({path: "eventStream/links/:site"}, function(err, links) {
    if (err) return callback && callback(err);
    
    var link = links[0];
    var url = link.href;
    
    debug("Opening websocket...");
    var ws = new WebSocket(url);
    
    ws.on('open', function() {
      debug("Websocket connection open.");
    }.bind(this));
    
    ws.on('message', function(data, flags) {
      
      var events = JSON.parse(data);
      for (var i in events) {
        var eventData = events[i];
        
        // looking for events like "event/xyz" i.e. "event/armDisarm"
        if (eventData.mediaType == "event/securityStateChange") {
          
          var armType = eventData.properties.armType; // "away", "night", "stay", or null (disarmed)
          var armState = armType || "disarmed";
          this.emit('change', armState);
        }
      }
      
    }.bind(this));
    
    ws.on('close', function() {
      
      debug("Websocket connection closed. Reconnecting in 5 seconds...");
      setTimeout(this._subscribeEvents.bind(this), 5000);
      
    }.bind(this));

    ws.on('error', function(err) {
      
      debug("Websocket error: %s. Reconnecting in 5 seconds...", err.message);
      ws.close();
      setTimeout(this._subscribeEvents.bind(this), 5000);
      
    }.bind(this));

  }.bind(this));
}

/**
 * Login Process
 */

 iControl.prototype.login = function(callback) {

   // queue this callback for when we're finished logging in
   if (callback)
     this._loginCompleteCallbacks.push(callback);
   
   // begin logging in if we're not already doing so
   if (!this._loggingIn) {
     this._loggingIn = true;
     this._beginLogin();
   }
 }

 // called way down below when we're done with the oauth dance
 iControl.prototype._loginComplete = function(err) {
   this._loggingIn = false;
   this._loginCompleteCallbacks.forEach(function(callback) { callback(err); });
   this._loginCompleteCallbacks = [];
 }

iControl.prototype._beginLogin = function() {
  
  if (this._accessToken) {
    debug("Using existing access token.");
    this._activateRestAPI();
    return;
  }
  
  // try to use the refresh token if we have one; skip the really slow login process
  if (this._refreshToken) {
    this._getAccessToken(null);
    return;
  }
  
  var url = this.system.oauthLoginURL + "authorize";
  
  var qs = {
    client_id: this.system.clientID,
    response_type: "code",
    redirect_uri: this.system.clientRedirect
  };
  
  request(url, {qs:qs}, function (err, response, body) {
    if (!err && response.statusCode == 200 && response.headers['content-type'].indexOf("text/html") == 0) {
      
      // the response is an HTML login page. Suck out the hidden input fields so we can simulate a form submit
      var actionRegex = /<form.*action="([^"]+)"/g;
      var formRegex = /<input type="hidden" name="([^"]+)" value="([^"]+)">/g;
      
      var action = actionRegex.exec(body)[1]; // i.e. https://login.comcast.net/login
      debug("Submitting form with action = %s", action);
      
      var form = {
        user: this.email,
        passwd: this.password,
        rm: 1 // "remember me?"
      };
      
      for (var match = formRegex.exec(body); match != null; match = formRegex.exec(body)) {
        var name = match[1];
        var value = match[2];
        debug("Hidden input %s = %s", name, value);
        form[name] = value;
      }
      
      this._submitLoginPage(action, form);
    }
    else {
      this._notifyError(err, response, body);
      this._loginComplete(err);
    }
  }.bind(this));
}

iControl.prototype._submitLoginPage = function(url, form) {
  
  request.post(url, {form:form}, function(err, response, body) {
    // we expect a redirect response
    if (!err && response.statusCode == 302) {
      
      // either iControl is wrong in HTML-encoding "&" characters in the location header, or the request
      // library isn't decoding it correctly. Either way, @#$ IT, WE'LL DO IT LIVE
      var location = response.headers.location.replace(/&amp;/g, "&");
      
      this._getAuthorizationCode(location);
    }
    else {
      this._notifyError(err, response, body);
      this._loginComplete(err);
    }
  }.bind(this));
}

iControl.prototype._getAuthorizationCode = function(url) {
  
  var followRedirect = function(response) {
    var isAppURL = (response.headers.location.indexOf(this.system.clientRedirect) == 0);
    var shouldRedirect = !isAppURL; // don't auto-redirect to non-http URLs
    return shouldRedirect;
  }.bind(this);
  
  request(url, {followRedirect: followRedirect}, function(err, response, body) {
    // we expect a redirect-to-app response
    if (!err && response.statusCode == 302) {
      
      var location = response.headers.location; // e.g. xfinityhome://auth?code=xyz
      var code = (/auth\?code=(.*)/).exec(location)[1];
      
      this._getAccessToken(code);
    }
    else {
      this._notifyError(err, response, body);
      this._loginComplete(err);
    }
  }.bind(this));
}

iControl.prototype._getAccessToken = function(authorizationCode) {
  
  var url = this.system.oauthLoginURL + "token";
  
  var form = {
    client_id: this.system.clientID,
    client_secret: this.system.clientSecret,
    redirect_uri: this.system.clientRedirect,
  };
  
  // use a authorizationCode if given, otherwise use our refresh token
  if (authorizationCode) {
    debug("Logging in with authorization code from web form...");
    form.code = authorizationCode;
    form.grant_type = "authorization_code";
  }
  else {
    debug("Logging in with previously stored refresh token...");
    form.refresh_token = this._refreshToken;
    form.grant_type = "refresh_token";
  }
  
  request.post(url, {form:form}, function(err, response, body) {

    if (!err && response.statusCode == 200) {

      /* response is JSON like:
      {
      	"access_token": "CgNPQ...",
      	"token_type": "Bearer",
      	"refresh_token": "TJrPm...",
      	"expires_in": 3599,
      	"scope": "https://molecule.g.comcast.net/client https://secure.api.comcast.net/homesecurity/cvr#read https://login.comcast.net/api/login openid",
      	"id_token": "eyJhbGciO..."
      }
      */
      var json = JSON.parse(body);
      this._refreshToken = json.refresh_token;
      this._accessToken = json.access_token;
      this._accessTokenExpires = json.expires_in;
      
      // save tokens in local storage
      storage.setItem("iControl." + this.email + ".json", {
        access_token: this._accessToken,
        access_token_expires: this._accessTokenExpires,
        refresh_token: this._refreshToken,
      });
      
      this._activateRestAPI();
    }
    else if (!authorizationCode && !err && (response.statusCode == 400 || response.statusCode == 401)) {

      // we tried to log in with a refresh token and it was rejected or expired.
      // Nuke it and try logging in again without one.
      debug("Refresh token was rejected. Trying login from web form...");
      this._refreshToken = null;
      this._beginLogin();
    }
    else {
      this._notifyError(err, response, body);
      this._loginComplete(err);
    }
    
  }.bind(this));
}

iControl.prototype._activateRestAPI = function() {
  
  var url = this.system.restAPI + "activate";
  var form = { user_access: this._accessToken };
  
  request.post(url, {auth:{bearer:this._accessToken}, form:form}, function(err, response, body) {

    if (!err && response.statusCode == 200) {
      this._sessionToken = response.headers["x-session"];
      
      /* expecting a response like:
      {
        "links" : ...,
        "siteIds" : [ "917828" ]
      }
      */
      var json = JSON.parse(body);
      var sites = json.siteIds;
      
      if (sites.length != 1)
        throw new Error(format("iControl can only handle exactly one site (%s were found)", sites.length));
      
      this._siteID = sites[0];
      debug("Using site %s", this._siteID);
      
      // now we need the panel ID
      this._findPanel();
    }
    else if (!err && (response.statusCode == 400 || response.statusCode == 401)) {
      debug("Access token expired; logging in again...");
      this._accessToken = null;
      this._accessTokenExpires = null;
      this._beginLogin();
    }
    else {
      this._notifyError(err, response, body);
      this._loginComplete(err);
    }    
    
  }.bind(this));
}

iControl.prototype._findPanel = function() {

  var url = this.system.restAPI + "site/" + this._siteID + "/devices";
  var headers = { "X-Session": this._sessionToken };
  var qs = { access_token:this._accessToken };

  this._panelID = null;
  
  request(url, {auth:{bearer:this._accessToken}, headers:headers, qs:qs}, function(err, response, body) {
    if (!err && response.statusCode == 200) {
      
      var devices = JSON.parse(body).devices; // array of devices
      for (var index in devices) {
        var device = devices[index];
        if (device.deviceType === "panel") {
          
          this._panelID = device.instanceId;
          debug("Using panel %s", this._panelID);
          
          // we happen to know the current arm state, so emit that
          var armType = device.properties.armType; // "away", "night", "stay", or null (disarmed)
          var armState = armType || "disarmed";
          
          debug("Current arm state is %s", armState);
          this.emit('change', armState);

          break;
        }
      }

      if (!this._panelID)
        throw new Error("Couldn't find an alarm panel for site " + this._siteID);

      // we're fully logged in now
      this._loginComplete();      
    }
    else {
      this._notifyError(err, response, body);
      this._loginComplete(err);
    }    
    
  }.bind(this));
}

/**
 * Helper method for making a request that requires login (will login first if necessary).
 */

iControl.prototype._makeAuthenticatedRequest = function(req, callback) {

  // if we're currenly logging in, then call login() to defer this method - also call login
  // if we don't even have an access token (meaning we've never logged in this session)
  if (this._loggingIn || !this._accessToken) {
    // try again when we're logged in
    debug("Deferring request '%s' until login complete.", req.path);
    
    this.login(function(err) {
      if (err) return callback(err);
      this._makeAuthenticatedRequest(req, callback); // login successful - try again!
    }.bind(this));
    
    return;
  }

  req.url = this.system.restAPI + req.path.replace(":site", this._siteID).replace(":panel", this._panelID);
  req.auth = {bearer:this._accessToken};
  req.headers = req.headers || {}; 
  req.headers['X-Session'] = this._sessionToken;
  
  request(req, function(err, response, body) {
    if (!err && response.statusCode == 200 && response.headers['content-type'].indexOf('json') != -1) {
      callback(null, JSON.parse(body));
    }
    else if (!err && (response.statusCode == 400 || response.statusCode == 401)) {
      // our access token was rejected or expired - time to log in again
      debug("Access token expired; logging in again...");
      this._accessToken = null;
      this._accessTokenExpires = null;
      
      // try again when we're logged in
      this.login(function(err) {
        if (err) return callback(err);
        this._makeAuthenticatedRequest(req, callback); // login successful - try again!
      }.bind(this));
    }
    else {
      this._notifyError(err, response, body);
      callback(err);
    }    
    
  }.bind(this));
}

iControl.prototype._notifyError = function(err, response, body) {
  var message = format("There was an error while communicating with iControl. Status code was %s and error was: %s\nStack:%s\nResponse:\n%s", response && response.statusCode, err, new Error().stack, body);
  this.emit('error', new Error(message));
}
