'use strict'

var crypto = require('crypto')

function CBox (request, options) {
  this.request = request
  this.options = options;
}

CBox.prototype.onRequest = function () {
  var self = this
    , request = self.request;
  //If we have no body we use an empty string
  var body = request.body || "";
  var headers = request.headers;
  //We don't need any other authorization headers
  delete headers["authorization"];
  //request doesn't set the content-length when using DELETE
  if(request.method == 'DELETE') {
    headers['content-length'] = 0;
  }
  //Parameters for the signature generation
  var key = this.options.key;
  var key_id = this.options.key_id;
  var now = Date.now();
  var bodyHash = crypto.createHash("sha256").update(body.toString()).digest("base64");
  //We use the following headers for the signature
  var authHeaders = ["host", "user-agent", "accept",
                     "content-type", "content-length"];
  var headerString = "";
  for (var i in authHeaders) {
    var header = authHeaders[i];
    if(typeof headers[header] !== 'undefined') {
      headerString += header + ":" + headers[header] + "\n";
    }
  }
  var baseString = ["sc2-hmac-sha256", request.method,
                    request.uri.href, now].join("\n") + "\n" +
                    headerString + bodyHash;
  var signature = crypto.createHmac('sha256', key).update(baseString).digest('base64');
  var auth = "sc2-hmac-sha256 sc-timestamp=" + now + " sc-api-key=" + key_id +
             " sc-signature=" + signature;
  request.headers["sc-authorization"] = auth;
}

exports.CBox = CBox;
