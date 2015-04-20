'use strict'

var crypto = require('crypto')

function CBox (request) {
  this.request = request
}

CBox.prototype.onRequest = function (_cbox) {
  var self = this
    , request = self.request;
  var body = request.body || "";
  var headers = request.headers;
  var key = _cbox.key;
  var key_id = _cbox.key_id;
  var now = Date.now();
  var bodyHash = crypto.createHash("sha256").update(body).digest("base64");
  delete headers["authorization"];
  delete headers["sc-authorization"];
  var headerString = "";
  for (var header in headers) {
    headerString += header + ":" + headers[header] + "\n";
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
