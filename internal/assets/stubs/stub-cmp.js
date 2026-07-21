window.__sinkholeStubs = window.__sinkholeStubs || {};
window.__sinkholeStubs["cmp"] = true;
(function () {
  var tcData = { tcString: "", gdprApplies: false, eventStatus: "tcloaded", cmpStatus: "loaded", listenerId: null, cmpId: 0, cmpVersion: 1, isServiceSpecific: true, purpose: { consents: {} }, vendor: { consents: {} } };
  window.__tcfapi = function (cmd, ver, cb) {
    if (typeof cb !== "function") return;
    if (cmd === "ping") { cb({ gdprApplies: false, cmpLoaded: true, cmpStatus: "loaded", displayStatus: "hidden", apiVersion: "2.0" }, true); }
    else if (cmd === "removeEventListener") { cb(true); }
    else { cb(tcData, true); }
  };
  window.__gpp = function (cmd, cb) { if (typeof cb === "function") cb({ gppVersion: "1.1", cmpStatus: "loaded", cmpDisplayStatus: "hidden", signalStatus: "ready", gppString: "", applicableSections: [] }, true); };
})();
