___twitsecret = {
    configured: false,
    enabled: false,

    init: function() {
        var prefs = Components.classes["@mozilla.org/preferences-service;1"].getService( Components.interfaces.nsIPrefService );
        prefs = prefs.getBranch( "extensions.twitsecret." );
        ___twitsecret.configured = prefs.getBoolPref( "configured" );
        ___twitsecret.enable();
    },

    configure: function() {
        var token = ___twitsecret.api.requestToken();
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
        appcontent.addEventListener( "DOMContentLoaded", ___twitsecret.docload, true );
        ___twitsecret.enabled = true;
        ___twitsecret.updateStatus();
    },

    disable: function() {
        var appcontent = document.getElementById( 'appcontent' );
        if (! appcontent) {
            ___twitsecret.logError( 'Unable to obtain appcontent' );
            return;
        }
        appcontent.removeEventListener( "DOMContentLoaded", ___twitsecret.docload, true );
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

    docload: function( e ) {
        var win = e.originalTarget.defaultView;
        if (win.top != win) {
            return;
        }
        win.addEventListener( 'load', ___twitsecret.pageload, false );
    },

    pageload: function( e ) {
        alert( 'loaddone' );
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

        generateSignature: function( method, url, params ) {
            params.sort();
            var str = method + "&" + encodeURIComponent( url ) + "&" + encodeURIComponent( params.join( "&" ) );
            return b64_hmac_sha1( ___twitsecret.keys.secretKey + "&", str );
        },

        escapeParamKeyValue: function( value, index, arrayobj ) {
            var split = value.indexOf( "=" );
            return encodeURIComponent( value.substring( 0, split ) ) + '=' + encodeURIComponent( value.substring( split + 1 ) );
        },

        quoteParamValue: function( value, index, arrayobj ) {
            var split = value.indexOf( "=" );
            return value.substring( 0, split ) + '="' + value.substring( split + 1 ) + '"';
        },

        requestToken: function() {
            var method = "POST";
            var url = "https://api.twitter.com/oauth/request_token";
            var params = new Array();
            params.push( 'oauth_callback=chrome://twitsecret/content/requestTokenCallback.html' );
            params.push( 'oauth_consumer_key=' + ___twitsecret.keys.consumerKey );
            params.push( 'oauth_nonce=' + ___twitsecret.api.generateNonce() );
            params.push( 'oauth_signature_method=HMAC-SHA1' );
            params.push( 'oauth_timestamp=' + Math.floor( (new Date()).getTime() / 1000 ) );
            params.push( 'oauth_version=1.0' );
            params = params.map( ___twitsecret.api.escapeParamKeyValue );
            params.push( encodeURIComponent( 'oauth_signature' ) + '=' + encodeURIComponent( ___twitsecret.api.generateSignature( method, url, params ) ) );

            var authHeader = "OAuth " + params.map( ___twitsecret.api.quoteParamValue ).join( ", " );

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
            ___twitsecret.logError( "XHR success body: " + xhr.responseText );
            return null;
        },
    },
}

window.addEventListener( 'load', ___twitsecret.init, false );
