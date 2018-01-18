/// <reference path="oidc-client.js" />

///////////////////////////////
// config
///////////////////////////////
Oidc.Log.logger = console;
Oidc.Log.level = Oidc.Log.NONE;

var settings = {
    authority: "http://auth.sso.com",
    client_id: "website4",
    redirect_uri: window.location.protocol + "//" + window.location.host + "/index.html",
    post_logout_redirect_uri: window.location.protocol + "//" + window.location.host + "/index.html",

    // these two will be done dynamically from the buttons clicked, but are
    // needed if you want to use the silent_renew
    response_type: "id_token token",
    scope: "openid profile api_cv_profile",

    // silent renew will get a new access_token via an iframe 
    // just prior to the old access_token expiring (60 seconds prior)
    silent_redirect_uri: window.location.protocol + "//" + window.location.host + "/silent-renew.html",
    automaticSilentRenew: true,

    // will raise events for when user has performed a logout at IdentityServer
    monitorSession : true,

    // this will allow all the OIDC protocol claims to vbe visible in the window. normally a client app 
    // wouldn't care about them or want them taking up space
    filterProtocolClaims: true,

    // this will use the user info endpoint if it's an OIDC request and there's an access_token
    loadUserInfo: true,

    userStore: new Oidc.WebStorageStateStore({ store: window.localStorage })
};
var mgr = new Oidc.UserManager(settings);

///////////////////////////////
// events
///////////////////////////////
var user;
mgr.events.addUserLoaded(function (u) {
    user = u;
    gp.heading.config.user = {
        name: u.profile.given_name + " " + u.profile.family_name
    };
    gp.heading.render();
    console.log("user loaded");
    log("user loaded");
    showUser(user);
});

mgr.events.addUserUnloaded(function () {
    user = null;
    gp.heading.config.user = null;
    gp.heading.render();
    console.log("user unloaded");
    log("user unloaded");
    showUser();
});

mgr.events.addAccessTokenExpiring(function () {
    console.log("token expiring");
    log("token expiring");
    showUser(user);
});

mgr.events.addAccessTokenExpired(function () {
    console.log("token expired");
    log("token expired");
    showUser(user);
});

mgr.events.addSilentRenewError(function (e) {
    console.log("silent renew error", e.message);
    log("silent renew error", e.message);
});

mgr.events.addUserSignedOut(function () {
    console.log("user signed out");
    log("user signed out");
});

///////////////////////////////
// UI event handlers
///////////////////////////////
[].forEach.call(document.querySelectorAll(".request"), function (button) {
    button.addEventListener("click", function () {
        signIn(this.dataset["scope"], this.dataset["type"]);
    });
});
Array.prototype.slice.call(document.querySelectorAll('.call-api')).forEach(function(ca) {
    ca.addEventListener("click", callApi, false);
});
//document.querySelector(".logout").addEventListener("click", signOut, false);

///////////////////////////////
// functions for UI elements
///////////////////////////////
function signIn(scope, response_type) {
    mgr.signinRedirect({ scope: scope, response_type: response_type }).then(null, function (e) {
        log(e);
    });
}

function signInCallback() {
    mgr.signinRedirectCallback().then(function (user) {
        var hash = window.location.hash.substr(1);
        var result = hash.split('&').reduce(function (result, item) {
            var parts = item.split('=');
            result[parts[0]] = parts[1];
            return result;
        }, {});
        log(result);
    }).catch(function (error) {
        log(error);
    });
}

function signOut() {
    mgr.signoutRedirect();
}

function callApi(evt) {
    var action = evt.target.dataset.action;
    var xhr = new XMLHttpRequest();

    xhr.onload = function () {
        if (xhr.status >= 400) {
            logAjaxResult({
                status: xhr.status,
                statusText: xhr.statusText,
                wwwAuthenticate: xhr.getResponseHeader("WWW-Authenticate")
            });
        }
        else {
            if (action === "show-languages" || action === "update-languages" || action === "update-photo") {
                logAjaxResult(JSON.parse(xhr.responseText));
            } else {
                var fr = new FileReader();
                fr.onload = function () {
                    logImageResult(fr.result);
                };

                fr.readAsDataURL(xhr.response);
            }
        }
    };

    xhr.onerror = function () {
        if (xhr.status === 401) {
            mgr.removeUser();
        }

        logAjaxResult({
            status: xhr.status,
            statusText: xhr.statusText,
            wwwAuthenticate: xhr.getResponseHeader("WWW-Authenticate")
        });
    };

    var baseUri = "http://public-api-cv-profile.sso/";
    var method = "GET";
    var path = "languages";
    var data = null;
    var dummyWait = 1;

    switch (action) {
        case "show-languages":
            break;
        case "update-languages":
            var kl = document.querySelector("#known-languages").value.split(",").filter(e => !!e);

            if (kl.length === 0) {
                alert("wprowadź jakiś język");

                return;
            }

            document.querySelector("#known-languages").value = "";

            method = "PUT";
            data = JSON.stringify(kl);
            break;
        case "show-photo":
            path = "photo";
            break;
        case "update-photo":
            var files = document.querySelector("#photo").files;

            if (files.length !== 1) {
                alert("wybierz dokładnie jeden plik (JPEG)");

                return;
            }

            var file = files[0];
            var fr = new FileReader();
            fr.onload = function () {
                data = fr.result;
            };
            fr.readAsArrayBuffer(file);

            method = "POST";
            path = "photo";
            dummyWait = 1000;
            break;
    }

    xhr.open(method, baseUri + path, true);

    switch (action) {
        case "update-languages":
            xhr.setRequestHeader("Content-Type", "application/json");
            break;
        case "show-photo":
            xhr.responseType = "blob";
            break;
        case "update-photo":
            xhr.setRequestHeader("Content-Type", "image/jpeg");

            break;
    }

    if (user) {
        xhr.setRequestHeader("Authorization", "Bearer " + user.access_token);
    }

    // Tak, tak - wiem, że to beznadziejne jak cholera, ale nie to jest strasznie śmieciowy kod.
    window.setTimeout(function() {
        xhr.send(data);
    }, dummyWait);
}

function checkSessionState(user) {
    mgr.metadataService.getCheckSessionIframe().then(function (url) {
        if (url && user && user.session_state) {
            console.log("setting up check session iframe for session state", user.session_state);
            document.getElementById("rp").src = "check_session.html#" +
                "session_state=" + user.session_state +
                "&check_session_iframe=" + url +
                "&client_id=" + mgr.settings.client_id
            ;
        }
        else {
            console.log("no check session url, user, or session state: not setting up check session iframe");
            document.getElementById("rp").src = "about:blank";
        }
    });
}

window.onmessage = function (e) {
    if (e.origin === window.location.protocol + "//" + window.location.host && e.data === "changed") {
        console.log("user session has changed");
        mgr.removeUser();
        mgr.signinSilent().then(function () {
            // Session state changed but we managed to silently get a new identity token, everything's fine
            console.log('renewTokenSilentAsync success');
        }).catch(function (err) {
            // Here we couldn't get a new identity token, we have to ask the user to log in again
            console.log('renewTokenSilentAsync failed', err.message);
        });
    }
}

///////////////////////////////
// init
///////////////////////////////

// clears any old stale requests from storage
mgr.clearStaleState().then(function () {
    console.log("Finished clearing old state");
}).catch(function (e) {
    console.error("Error clearing state:", e.message);
});

// checks to see if we already have a logged in user
mgr.getUser().then(function (user) {
    showUser(user);
}).catch(function (e) {
    log(e);
});

// checks to see if the page being loaded looks like a login callback
if (window.location.hash) {
    signInCallback();
}

///////////////////////////////
// debugging helpers
///////////////////////////////
function log(msg) {
    display("#response", msg);
}
function logIdToken(msg) {
    display("#id-token", msg);
}
function logAccessToken(msg) {
    display("#access-token", msg);
}
function logAjaxResult(msg) {
    display("#ajax-result", msg, "pre");
}
function logImageResult(msg) {
    display("#ajax-result", msg, "img");
}
function display(selector, msg, mode = "normal") {
    document.querySelector(selector).innerText = '';

    if (msg) {
        if (msg instanceof Error) {
            msg = "Error: " + msg.message;
        }
        else if (typeof msg !== 'string') {
            msg = JSON.stringify(msg, null, 2);
        }

        if (mode === "pre") {
            msg = "<pre>" + msg + "</pre>";
        }

        if (mode === "img") {
            msg = "<img src='" + msg + "' style='max-width: 200px;' />";
        }

        document.querySelector(selector).innerHTML += msg + '\r\n';
    }
}

function showUser(user) {
    if (!user) {
        log("user not signed in");
        logIdToken();
        logAccessToken();
        logAjaxResult();
    }
    else {
        if (user.profile) {
            logIdToken({ profile: user.profile, session_state: user.session_state });
        }
        else {
            logIdToken();
        }
        if (user.access_token) {
            logAccessToken({ access_token: user.access_token, expires_in: user.expires_in, scope: user.scope });
        }
        else {
            logAccessToken();
        }
    }
}