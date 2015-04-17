/* -*- mode: js; indent-tabs-mode: nil; js-indent-level: 2 -*- */
"use strict";

let windows = require("sdk/windows");
let {viewFor} = require("sdk/view/core");
let self = require("sdk/self");
const {Cc, Ci} = require("chrome");

let gSSService = Cc["@mozilla.org/ssservice;1"].getService(Ci.nsISiteSecurityService);

function ProgressListener(win) {
  this._win = win;
  this._doneOne = false;
  this._lastState = 0;
  this._lastLocation = "";
}

ProgressListener.prototype.onSecurityChange = function(webProgress, request, state) {
  let uri = this._win.gBrowser.currentURI;
  if (this._doneOne && state === this._lastState && uri.spec === this._lastLocation)
    return;
  this._doneOne = true;
  this._lastState = state;
  this._lastLocation = uri.spec;
  let label = this._win.document.getElementById("httpsinfo-label");
  if (!(state & (Ci.nsIWebProgressListener.STATE_IS_SECURE | Ci.nsIWebProgressListener.STATE_IS_BROKEN))) {
    label.collapsed = true;
    return;
  }

  const nsISSLStatus = Ci.nsISSLStatus;
  let sslStatus = this._win.gBrowser.securityUI.SSLStatus;
  let protocolVersion;
  switch (sslStatus.protocolVersion) {
  case nsISSLStatus.TLS_VERSION_1:
    protocolVersion = "1.0";
    break;
  case nsISSLStatus.TLS_VERSION_1_1:
    protocolVersion = "1.1";
    break;
  case nsISSLStatus.TLS_VERSION_1_2:
    protocolVersion = "1.2";
    break;
  default:
    protocolVersion = "?";
    break;
  }
  let suite = sslStatus.cipherName;
  let pfs = suite.contains("DHE_");
  let cipher = suite.contains("_AES_") ? "AES" :
      (suite.contains("_RC4_") ? "RC4" :
       (suite.contains("_3DES_") ? "DES" : "?"));
  let mode = suite.contains("_GCM_") ? "/GCM" :
      (suite.contains("_CBC_") ? "/CBC" :
       (cipher === "RC4" ? "" : "/?"));
  let h2 = false;
  let httpInternal = request.QueryInterface(Ci.nsIHttpChannelInternal);
  if (httpInternal !== null) {
    let major = {} , minor = {};
    httpInternal.getResponseVersion(major, minor);
    if (major.value === 2)
      h2 = true;
  }
  let sts = gSSService.isSecureURI(Ci.nsISiteSecurityService.HEADER_HSTS, uri, 0);
  label.value = `${protocolVersion},${cipher}/${sslStatus.secretKeyLength}${mode},${pfs ? "FS" : "!FS"},${sts ? "STS" : "!STS"}${h2 ? ",H2" : ""}`;
  label.tooltipText = sslStatus.cipherName;

  label.collapsed = false;
};

function applyToWindow(modelWin) {
  let win = viewFor(modelWin);

  {
    // Add our stylesheet.
    let style = win.document.createProcessingInstruction("xml-stylesheet", 'class="httpsinfo-node" href="' + self.data.url("httpsinfo.css") + '" type="text/css"')
    win.document.insertBefore(style, win.document.firstChild);
  }

  {
    // Add label to the URLBar.
    let label = win.document.createElement("label");
    label.setAttribute("id", "httpsinfo-label");
    label.setAttribute("class", "plain");
    label.collapsed = true;
    let identityBox = win.document.getElementById("identity-box");
    let identityLabels = win.document.getElementById("identity-icon-labels");
    identityBox.insertBefore(label, identityLabels);
  }

  win.gHTTPSInfoListener = new ProgressListener(win);
  win.gBrowser.addProgressListener(win.gHTTPSInfoListener);
}

function removeFromWindow(modelWin) {
  let win = viewFor(modelWin);
  if ("gHTTPSInfoListener" in win) {
    win.gBrowser.removeProgressListener(win.gHTTPSInfoListener);
    delete win["gHTTPSInfoListener"];
  }

  {
    let label = win.document.getElementById("httpsinfo-label");
    if (label !== null) {
      label.parentNode.removeChild(label);
    }
  }

  for (let child = win.document.firstChild; child !== null; child = child.nextSibling) {
    if (child.nodeType === child.PROCESSING_INSTRUCTION_NODE &&
        child.data.contains("httpsinfo-node")) {
      child.parentNode.removeChild(child);
    }
  }
}

exports.main = (function (options, callbacks) {
  for (let win of windows.browserWindows) {
    applyToWindow(win);
  }
  windows.browserWindows.on("open", function(win) {
    applyToWindow(win);
  });
  windows.browserWindows.on("close", function(win) {
    removeFromWindow(win);
  });
});

exports.onUnload = (function (reason) {
  for (let win of windows.browserWindows) {
    removeFromWindow(win);
  }
});
