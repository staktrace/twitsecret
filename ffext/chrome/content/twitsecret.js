___twitsecret = {
    configured: false,
    enabled: false,
    requestTokens: null,

    prefs: function() {
        var prefs = Components.classes["@mozilla.org/preferences-service;1"].getService( Components.interfaces.nsIPrefService );
        prefs = prefs.getBranch( "extensions.twitsecret." );
        return prefs;
    },

    init: function() {
        var prefs = ___twitsecret.prefs();
        ___twitsecret.configured = prefs.getBoolPref( "configured" );
        ___twitsecret.enable();
    },

    configure: function() {
        if (___twitsecret.requestTokens != null) {
            var requestTokenList = ___twitsecret.requestTokens;
            ___twitsecret.requestTokens = null;

            var pinCode = prompt( 'Please enter the PIN code obtained from Twitter' );
            if (pinCode == null) {
                return;
            }
            var accessTokens = ___twitsecret.api.getAccessToken( requestTokenList, pinCode );
            if (accessTokens != null) {
                var prefs = ___twitsecret.prefs();
                ___twitsecret.configured = true;
                var desiredParams = ['oauth_token', 'oauth_token_secret', 'user_id', 'screen_name'];
                for (var key in desiredParams) {
                    var keyVal = ___twitsecret.api.getResponseValue( accessTokens, desiredParams[key] );
                    if (keyVal == null) {
                        ___twitsecret.logError( 'Did not find [' + desiredParams[key] + '] in accessToken response' );
                        ___twitsecret.configured = false;
                        break;
                    }
                    prefs.setCharPref( desiredParams[key], keyVal );
                }
                prefs.setBoolPref( "configured", ___twitsecret.configured );
            }
            return;
        }

        var requestTokenList = ___twitsecret.api.getRequestToken();
        if (requestTokenList == null) {
            return;
        }

        var token = ___twitsecret.api.getResponseValue( requestTokenList, 'oauth_token' );
        if (token == null) {
            ___twitsecret.logError( 'Did not find oauth_token in the response' );
            return;
        }
        var authorizeUrl = 'https://api.twitter.com/oauth/authorize?oauth_token=' + token;

        alert( 'Please authenticate yourself at the Twitter website that will load in a few seconds. Once you have obtained the PIN, click on the TwitSecret button again to complete the procedure.' );
        gBrowser.loadOneTab( authorizeUrl, { inBackground: false } );
        ___twitsecret.requestTokens = requestTokenList;
    },

    enable: function() {
        if (! ___twitsecret.configured) {
            ___twitsecret.logError( 'Cannot enable; not yet configured' );
            return;
        }

        var appcontent = document.getElementById( 'appcontent' );
        if (! appcontent) {
            ___twitsecret.logError( 'Unable to obtain appcontent' );
            return;
        }
        appcontent.addEventListener( "DOMContentLoaded", ___twitsecret.mutator.pageloaded, true );
        ___twitsecret.enabled = true;
        ___twitsecret.updateStatus();
    },

    disable: function() {
        var appcontent = document.getElementById( 'appcontent' );
        if (! appcontent) {
            ___twitsecret.logError( 'Unable to obtain appcontent' );
            return;
        }
        appcontent.removeEventListener( "DOMContentLoaded", ___twitsecret.mutator.pageloaded, true );
        ___twitsecret.enabled = false;
        ___twitsecret.updateStatus();
    },

    toggle: function() {
        if (! ___twitsecret.configured) {
            ___twitsecret.configure();
        }
        if (! ___twitsecret.enabled) {
            ___twitsecret.enable();
        } else {
            ___twitsecret.disable();
        }
    },

    updateStatus: function() {
        document.getElementById( 'twitsecret-statusbar-panel' ).setAttribute( 'label', 'TwitSecret is ' + (___twitsecret.enabled ? 'ON' : 'OFF') );
    },

    logError: function( errmsg ) {
        Components.utils.reportError( "TwitSecret: " + errmsg );
    },

    mutator: {
        pageloaded: function( e ) {
            var win = e.originalTarget.defaultView;
            if (win.top != win) {
                return;
            }
            // TODO: mutate pages here
        },
    },

    api: {
        generateNonce: function() {
            var chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXY0123456789';
            var nonce = "";
            for (var i = 0; i < 16; i++) {
                nonce = nonce + chars.charAt( Math.floor( Math.random() * chars.length ) );
            }
            return nonce;
        },

        generateTimestamp: function() {
            return Math.floor( (new Date()).getTime() / 1000 );
        },

        generateSignature: function( method, url, params, keyTail ) {
            params.sort();
            var str = method + "&" + encodeURIComponent( url ) + "&" + encodeURIComponent( params.join( "&" ) );
            if (typeof keyTail == 'string') {
                keyTail = '&' + keyTail;
            } else {
                keyTail = '&';
            }
            return b64_hmac_sha1( ___twitsecret.keys.secretKey + keyTail, str );
        },

        escapeParamKeyValue: function( value, index, arrayobj ) {
            var split = value.indexOf( "=" );
            return encodeURIComponent( value.substring( 0, split ) ) + '=' + encodeURIComponent( value.substring( split + 1 ) );
        },

        quoteParamValue: function( value, index, arrayobj ) {
            var split = value.indexOf( "=" );
            return value.substring( 0, split ) + '="' + value.substring( split + 1 ) + '"';
        },

        getResponseValue: function( responseArray, keyName ) {
            for (var i = 0; i < responseArray.length; i++) {
                if (responseArray[i].indexOf( keyName + '=' ) == 0) {
                    return responseArray[i].substring( keyName.length + 1 );
                }
            }
            return null;
        },

        makeRequest: function( method, url, authParams ) {
            var authHeader = "OAuth " + authParams.map( ___twitsecret.api.quoteParamValue ).join( ", " );
            var xhr = new XMLHttpRequest();
            xhr.open( method, url, false );
            xhr.setRequestHeader( 'Authorization', authHeader );
            xhr.send( null );
            if (xhr.readyState != 4) {
                ___twitsecret.logError( "XHR ended with ready state " + xhr.readyState );
                return null;
            }
            if (xhr.status != 200) {
                ___twitsecret.logError( "XHR ended with status " + xhr.status );
                ___twitsecret.logError( "XHR body: " + xhr.responseText );
                return null;
            }
            return xhr.responseText.split( '&' );
        },

        getRequestToken: function() {
            var method = "POST";
            var url = "https://api.twitter.com/oauth/request_token";
            var params = new Array();
            params.push( 'oauth_callback=oob' );
            params.push( 'oauth_consumer_key=' + ___twitsecret.keys.consumerKey );
            params.push( 'oauth_nonce=' + ___twitsecret.api.generateNonce() );
            params.push( 'oauth_signature_method=HMAC-SHA1' );
            params.push( 'oauth_timestamp=' + ___twitsecret.api.generateTimestamp() );
            params.push( 'oauth_version=1.0' );
            params = params.map( ___twitsecret.api.escapeParamKeyValue );
            params.push( encodeURIComponent( 'oauth_signature' ) + '=' + encodeURIComponent( ___twitsecret.api.generateSignature( method, url, params, null ) ) );

            var response = ___twitsecret.api.makeRequest( method, url, params );
            if (response == null) {
                return null;
            }
            for (var i = 0; i < response.length; i++) {
                if (response[i] == 'oauth_callback_confirmed=true') {
                    response.splice( i, 1 );
                    return response;
                }
            }
            ___twitsecret.logError( "XHR response didn't contain confirmation; response: " + response );
            return null;
        },

        getAccessToken : function( requestTokenList, pinCode ) {
            var method = "POST";
            var url = "https://api.twitter.com/oauth/access_token";
            var params = new Array();
            params.push( 'oauth_consumer_key=' + ___twitsecret.keys.consumerKey );
            params.push( 'oauth_nonce=' + ___twitsecret.api.generateNonce() );
            params.push( 'oauth_signature_method=HMAC-SHA1' );
            params.push( 'oauth_token=' + ___twitsecret.api.getResponseValue( requestTokenList, 'oauth_token' ) );
            params.push( 'oauth_timestamp=' + ___twitsecret.api.generateTimestamp() );
            params.push( 'oauth_verifier=' + pinCode );
            params.push( 'oauth_version=1.0' );
            params = params.map( ___twitsecret.api.escapeParamKeyValue );
            var tokenSecret = ___twitsecret.api.getResponseValue( requestTokenList, 'oauth_token_secret' );
            params.push( encodeURIComponent( 'oauth_signature' ) + '=' + encodeURIComponent( ___twitsecret.api.generateSignature( method, url, params, tokenSecret ) ) );

            var response = ___twitsecret.api.makeRequest( method, url, params );
            return response;
        }
    },
}

window.addEventListener( 'load', ___twitsecret.init, false );
