___twitsecret = {
    configured: false,
    enabled: false,
    requestTokens: null,
    secretFriends: null,
    password: "password",   // TODO replace this with a password obtained from user on configure and enable
    pollInterval: 3000,
    dataCache: {},
    htmlTemplate: '<div class="stream-item" data-item-type="tweet" data-item-id="__TWEETID__" media="true"><div class="more">»</div> <div class="stream-item-content tweet stream-tweet " data-tweet-id="__TWEETID__" data-item-id="__TWEETID__" data-screen-name="__SCREENNAME__" data-user-id="__USERID__"> <div class="tweet-dogear "></div> <div class="tweet-image"> <img src="__ICONURL__" alt="__USERNAME__" class="user-profile-link" data-user-id="__USERID__" height="48" width="48"> </div> <div class="tweet-content"> <div class="tweet-row"> <span class="tweet-user-name"> <a class="tweet-screen-name user-profile-link" data-user-id="__USERID__" href="/#%21/__SCREENNAME__" title="__USERNAME__">__SCREENNAME__</a> <span class="tweet-full-name">__USERNAME__</span> </span> <div class="tweet-corner"> <div class="tweet-meta"> <span class="icons"> <div class="extra-icons"> <span class="inlinemedia-icons"></span> </div> </span> </div> </div> </div> <div class="tweet-row"> <div class="tweet-text">__TEXT__</div> </div> <div class="tweet-row"> </div> <div class="tweet-row"> <a href="/#%21/__SCREENNAME__/status/__TWEETID__" class="tweet-timestamp" title="__TIMEDATE__"><span class="_timestamp" data-time="__TIMEMILLIS__" data-long-form="true">__TIMEAPPROX__</span></a> <span class="tweet-actions" data-tweet-id="__TWEETID__"> <a href="#" class="favorite-action"><span><i></i><b>Favorite</b></span></a> <a href="#" class="reply-action" data-screen-name="__SCREENNAME__"><span><i></i><b>Reply</b></span></a> <a href="#" class="delete-action"><span><i></i><b>Delete</b></span></a> </span> </div> <div class="tweet-row"> </div> </div> </div></div>',

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
                if (___twitsecret.configured) {
                    var userId = prefs.getCharPref( 'user_id' );
                    var pubkey = ___twitsecret.api.getKey( userId, true );
                    if (pubkey != null) {
                        ___twitsecret.backend.add( userId, pubkey );
                        alert( 'You already has a TwitSecret public key. Please install the private key to ~/.twitsecret/, or clear your Twitter "bio" field.' );
                    } else {
                        // first time user, publish key
                        var pubkey = ___twitsecret.backend.init( userId );
                        ___twitsecret.api.publishKey( pubkey );
                    }
                }
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
        appcontent.addEventListener( "DOMContentLoaded", ___twitsecret.mutator.pageLoaded, true );
        ___twitsecret.enabled = true;
        ___twitsecret.updateStatus();
    },

    disable: function() {
        var appcontent = document.getElementById( 'appcontent' );
        if (! appcontent) {
            ___twitsecret.logError( 'Unable to obtain appcontent' );
            return;
        }
        appcontent.removeEventListener( "DOMContentLoaded", ___twitsecret.mutator.pageLoaded, true );
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
        pageLoaded: function( e ) {
            var win = e.originalTarget.defaultView;
            if (win.location.hostname.indexOf( "twitter" ) < 0) {
                return;
            }
            try {
                ___twitsecret.mutator.addButton( win, 1 );
            } catch (e) {
                ___twitsecret.logError( e );
            }
            try {
                ___twitsecret.mutator.decryptStream( win, 1 );
            } catch (e) {
                ___twitsecret.logError( e );
            }
        },

        addButton: function( win, checkCount ) {
            var buttons = win.document.getElementsByClassName( "tweet-button" );
            if (buttons.length == 0) {
                if (checkCount >= 5) {
                    ___twitsecret.logError( "Giving up on adding button" );
                } else {
                    setTimeout( ___twitsecret.mutator.addButton, ___twitsecret.pollInterval, win, checkCount + 1 );
                }
            } else if (buttons.length == 1) {
                var button = buttons.item( 0 );
                var clone = win.document.createElement( 'a' );
                clone.className = button.className;
                clone.textContent = 'TweetSecretly';
                button.addEventListener( 'DOMAttrModified', function( e ) {
                    clone.className = button.className;
                }, false );
                button.parentNode.insertBefore( clone, button.nextSibling );
                clone.addEventListener( "click", ___twitsecret.mutator.encryptTweet, false );
            }
        },

        decryptStream: function( win, checkCount ) {
            var streams = win.document.getElementsByClassName( "stream-items" );
            if (streams.length == 0) {
                if (checkCount >= 5) {
                    ___twitsecret.logError( "Giving up on decrypting stream" );
                } else {
                    setTimeout( ___twitsecret.mutator.decryptStream, ___twitsecret.pollInterval, win, checkCount + 1 );
                }
            } else if (streams.length == 1) {
                var stream = streams.item( 0 );
                stream.innerHTML = ___twitsecret.mutator.getTimelineHTML();
            }
        },

        encryptTweet: function( e ) {
            var out = { accepted: false, friends: new Array() };
            var picker = window.openDialog( "chrome://twitsecret/content/picker.xul", "", "chrome, dialog, modal, resizable=yes", ___twitsecret, out );
            if (! out.accepted) {
                return;
            }

            var win = e.view;
            var texts = win.document.getElementsByClassName( "twitter-anywhere-tweet-box-editor" );
            if (texts.length != 1) {
                ___twitsecret.logError( "Found " + texts.length + " textarea elements" );
                alert( 'Unexpected TwitSecret error!' );
                return;
            }
            var textarea = texts.item( 0 );
            var msg = textarea.value;
            var encrypted = ___twitsecret.backend.encrypt( msg, out.friends.concat( ___twitsecret.prefs().getCharPref( 'user_id' ) ) );
            var numpackets = Math.ceil( (encrypted.length + 4) / 140 );
            if (numpackets < 10) {
                encrypted = "TS0" + numpackets + encrypted;
            } else if (numpackets < 99) {
                encrypted = "TS" + numpackets + encrypted;
            } else {
                alert( 'Sorry, the message is too long and/or you have too many recipients.' );
                return;
            }

            for (var i = numpackets - 1; i > 0; i--) {
                ___twitsecret.api.postTweet( encrypted.substr( 140 * i, 140 ) );
            }
            textarea.value = encrypted.substr( 0, 140 );
            var button = win.document.getElementsByClassName( "tweet-button" ).item( 0 );
            var e = win.document.createEvent( "MouseEvents" );
            e.initMouseEvent( "click", true, true, win, 0, 0, 0, 0, 0, false, false, false, false, 0, null );
            button.dispatchEvent( e );
        },

        getTimeline: function() {
            var tweets = ___twitsecret.api.getTweets();
            if (tweets == null) {
                ___twitsecret.logError( "Unable to fetch tweets" );
                return null;
            }
            var timeline = new Array();
            for (var i = 0; i < tweets.length && timeline.length < 20; i++) {
                var tweet = tweets[i];
                if (tweet.source == "web" && tweet.text.length >= 4 && tweet.text.substring( 0, 2 ) == "TS") { // TODO: this might pick up false positives
                    var numMsgs = parseInt( tweet.text.substring( 2, 4 ) );
                    if (! isNaN( numMsgs )) {
                        var ciphertext = tweet.text.substring( 4 );
                        numMsgs--;
                        for (var j = i + 1; j < tweets.length && numMsgs > 0; j++) {
                            if (tweets[j].user.id_str == tweet.user.id_str && tweets[j].source.indexOf( "twitsecret" ) >= 0) {
                                ciphertext += tweets[j].text;
                                tweets.splice( j, 1 );
                                j--;
                                numMsgs--;
                            }
                        }
                        if (numMsgs == 0) {
                            var plaintext = ___twitsecret.backend.decrypt( ciphertext, ___twitsecret.prefs().getCharPref( 'user_id' ) );
                            if (plaintext != null) {
                                tweet.text = plaintext;
                                // fall through to timeline.push
                            } else {
                                continue;
                            }
                        } else {
                            continue;
                        }
                    }
                }
                timeline.push( tweet );
            }
            return timeline;
        },

        approxTime: function( millis ) {
            var delta = (new Date().getTime() - millis) / 1000;
            if (delta < 60) {
                return Math.floor( delta ) + " seconds ago";
            } else if (delta < 60 * 60) {
                return Math.floor( delta / 60 ) + " minutes ago";
            } else if (delta < 60 * 60 * 24) {
                return Math.floor( delta / (60 * 60) ) + " hours ago";
            } else if (delta < 60 * 60 * 60 * 24 * 365) {
                return Math.floor( delta / (60 * 60 * 24) ) + " days ago";
            } else {
                return Math.floor( delta / (60 * 60 * 24 * 365) ) + " years ago";
            }
        },

        getTimelineHTML: function() {
            var timeline = ___twitsecret.mutator.getTimeline();
            if (timeline == null) {
                return null;
            }
            var html = "";
            for (var i = 0; i < timeline.length; i++) {
                var item = timeline[i];
                var itemHtml = ___twitsecret.htmlTemplate;
                var time = Date.parse( item.created_at );
                var timeApprox = ___twitsecret.mutator.approxTime( time );
                itemHtml = itemHtml.replace( /__TWEETID__/g, item.id_str );
                itemHtml = itemHtml.replace( /__SCREENNAME__/g, item.user.screen_name );
                itemHtml = itemHtml.replace( /__USERID__/g, item.user.id_str );
                itemHtml = itemHtml.replace( /__ICONURL__/g, item.user.profile_image_url );
                itemHtml = itemHtml.replace( /__USERNAME__/g, item.user.name );
                itemHtml = itemHtml.replace( /__TEXT__/g, item.text );
                itemHtml = itemHtml.replace( /__TIMEDATE__/g, item.created_at );
                itemHtml = itemHtml.replace( /__TIMEMILLIS__/g, time );
                itemHtml = itemHtml.replace( /__TIMEAPPROX__/g, timeApprox );
                html += itemHtml;
            }
            return html;
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

        urlencode: function( str ) {
            return encodeURIComponent( str ).replace( /!/g, '%21' )
                                            .replace( /'/g, '%27' )
                                            .replace( /\(/g, '%28' )
                                            .replace( /\)/g, '%29' )
                                            .replace( /\*/g, '%2A' );
        },

        addSignature: function( method, url, headerParams, postParams, keyTail ) {
            var params = (postParams == null ? headerParams.concat() : headerParams.concat( postParams ));
            var queryIx = url.indexOf( '?' );
            if (queryIx >= 0) {
                params = params.concat( url.substring( queryIx + 1 ).split( '&' ) );
                url = url.substring( 0, queryIx );
            }
            params.sort();
            var str = method + "&" + ___twitsecret.api.urlencode( url ) + "&" + ___twitsecret.api.urlencode( params.join( "&" ) );
            if (typeof keyTail != 'string') {
                keyTail = ___twitsecret.prefs().getCharPref( 'oauth_token_secret' );
            }
            var signature = b64_hmac_sha1( ___twitsecret.keys.secretKey + '&' + keyTail, str );
            headerParams.push( ___twitsecret.api.urlencode( 'oauth_signature' ) + '=' + ___twitsecret.api.urlencode( signature ) );
            return headerParams;
        },

        escapeParamKeyValue: function( value, index, arrayobj ) {
            var split = value.indexOf( "=" );
            return ___twitsecret.api.urlencode( value.substring( 0, split ) ) + '=' + ___twitsecret.api.urlencode( value.substring( split + 1 ) );
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

        makeRequest: function( method, url, authParams, postParams ) {
            var authHeader = "OAuth " + authParams.map( ___twitsecret.api.quoteParamValue ).join( ", " );
            var postBody = (postParams == null ? "" : postParams.join( "&" ));
            var xhr = new XMLHttpRequest();
            xhr.open( method, url, false );
            xhr.setRequestHeader( 'Authorization', authHeader );
            xhr.setRequestHeader( 'Content-Type', 'application/x-www-form-urlencoded' );
            xhr.setRequestHeader( 'Content-Length', postBody.length );
            xhr.send( postBody );
            if (xhr.readyState != 4) {
                ___twitsecret.logError( "XHR ended with ready state " + xhr.readyState );
                return null;
            }
            if (xhr.status != 200) {
                ___twitsecret.logError( "XHR ended with status " + xhr.status );
                ___twitsecret.logError( "XHR body: " + xhr.responseText );
                return null;
            }
            return xhr.responseText;
        },

        makeBaseParams: function( includeOauthToken ) {
            var params = new Array();
            params.push( 'oauth_consumer_key=' + ___twitsecret.keys.consumerKey );
            params.push( 'oauth_nonce=' + ___twitsecret.api.generateNonce() );
            params.push( 'oauth_signature_method=HMAC-SHA1' );
            params.push( 'oauth_timestamp=' + ___twitsecret.api.generateTimestamp() );
            params.push( 'oauth_version=1.0' );
            if (includeOauthToken) {
                params.push( 'oauth_token=' + ___twitsecret.prefs().getCharPref( 'oauth_token' ) );
            }
            return params;
        },

        getRequestToken: function() {
            var method = "POST";
            var url = "https://api.twitter.com/oauth/request_token";
            var params = ___twitsecret.api.makeBaseParams( false );
            params.push( 'oauth_callback=oob' );
            params = params.map( ___twitsecret.api.escapeParamKeyValue );
            params = ___twitsecret.api.addSignature( method, url, params, null, "" );

            var response = ___twitsecret.api.makeRequest( method, url, params, null );
            if (response != null) {
                response = response.split( '&' );
                for (var i = 0; i < response.length; i++) {
                    if (response[i] == 'oauth_callback_confirmed=true') {
                        response.splice( i, 1 );
                        return response;
                    }
                }
                ___twitsecret.logError( "XHR response didn't contain confirmation; response: " + response );
            }
            return null;
        },

        getAccessToken: function( requestTokenList, pinCode ) {
            var method = "POST";
            var url = "https://api.twitter.com/oauth/access_token";
            var params = ___twitsecret.api.makeBaseParams( false );
            params.push( 'oauth_token=' + ___twitsecret.api.getResponseValue( requestTokenList, 'oauth_token' ) );
            params.push( 'oauth_verifier=' + pinCode );
            params = params.map( ___twitsecret.api.escapeParamKeyValue );
            var tokenSecret = ___twitsecret.api.getResponseValue( requestTokenList, 'oauth_token_secret' );
            params = ___twitsecret.api.addSignature( method, url, params, null, tokenSecret );
            var response = ___twitsecret.api.makeRequest( method, url, params, null );
            if (response != null) {
                response = response.split( '&' );
            }
            return response;
        },

        verifyCredentials: function() {
            var method = "GET";
            var url = "https://api.twitter.com/1/account/verify_credentials.json";
            var params = ___twitsecret.api.makeBaseParams( true );
            params = params.map( ___twitsecret.api.escapeParamKeyValue );
            params = ___twitsecret.api.addSignature( method, url, params, null, null );
            return (___twitsecret.api.makeRequest( method, url, params, null ) != null);
        },

        publishKey: function( key ) {
            var method = "POST";
            var url = "https://api.twitter.com/1/account/update_profile.json?description=" + ___twitsecret.api.urlencode( "TwitSecret:" + key );
            var params = ___twitsecret.api.makeBaseParams( true );
            params = params.map( ___twitsecret.api.escapeParamKeyValue );
            params = ___twitsecret.api.addSignature( method, url, params, null, null );
            return (___twitsecret.api.makeRequest( method, url, params, null ) != null);
        },

        getFriends: function() {
            var method = "GET";
            var url = "https://api.twitter.com/1/friends/ids.json";
            var params = ___twitsecret.api.makeBaseParams( true );
            params = params.map( ___twitsecret.api.escapeParamKeyValue );
            params = ___twitsecret.api.addSignature( method, url, params, null, null );
            var response = ___twitsecret.api.makeRequest( method, url, params, null );
            if (response != null) {
                return JSON.parse( response );
            }
            return null;
        },

        getKey: function( userId, checkOnly ) {
            var method = "GET";
            var url = "https://api.twitter.com/1/users/show.json?user_id=" + userId;
            var params = ___twitsecret.api.makeBaseParams( true );
            params = params.map( ___twitsecret.api.escapeParamKeyValue );
            params = ___twitsecret.api.addSignature( method, url, params, null, null );
            var response = ___twitsecret.api.makeRequest( method, url, params, null );
            if (response != null) {
                response = JSON.parse( response );
                ___twitsecret.dataCache[ userId ] = response;
                response = response.description;
                if (response != null && response.indexOf( "TwitSecret:" ) == 0) {
                    return response.substring( 11 );
                }
                if (! checkOnly) {
                    ___twitsecret.logError( "Specified user is not using TwitSecret" );
                }
            }
            return null;
        },

        postTweet: function( msg ) {
            var method = "POST";
            var url = "https://api.twitter.com/1/statuses/update.json";
            var params = ___twitsecret.api.makeBaseParams( true );
            params = params.map( ___twitsecret.api.escapeParamKeyValue );
            var postParams = new Array();
            postParams.push( 'status=' + msg );
            postParams = postParams.map( ___twitsecret.api.escapeParamKeyValue );
            params = ___twitsecret.api.addSignature( method, url, params, postParams, null );
            return ___twitsecret.api.makeRequest( method, url, params, postParams );
        },

        getTweets: function() {
            var method = "GET";
            var url = "https://api.twitter.com/1/statuses/friends_timeline.json?count=200&include_rts=1";
            var params = ___twitsecret.api.makeBaseParams( true );
            params = params.map( ___twitsecret.api.escapeParamKeyValue );
            params = ___twitsecret.api.addSignature( method, url, params, null, null );
            var response = ___twitsecret.api.makeRequest( method, url, params, null );
            if (response != null) {
                response = JSON.parse( response );
            }
            return response;
        },
    },

    backend: {
        getPlatform: function() {
            var archCompiler = Components.classes["@mozilla.org/xre/app-info;1"].getService( Components.interfaces.nsIXULRuntime ).XPCOMABI;
            var ix = archCompiler.indexOf( "-" );
            return (ix < 0 ? archCompiler : archCompiler.substring( 0, ix ));
        },

        getProcess: function() {
            var myProjId = "projects.twitsecret.ffext@staktrace.com";
            var em = Components.classes["@mozilla.org/extensions/manager;1"].getService( Components.interfaces.nsIExtensionManager );
            var file = em.getInstallLocation( myProjId ).getItemFile( myProjId, "backend/" + ___twitsecret.backend.getPlatform() + "/twitsecret" );
            var process = Components.classes["@mozilla.org/process/util;1"].createInstance( Components.interfaces.nsIProcess );
            process.init( file );
            return process;
        },

        getFile: function( filename ) {
            var dirs = Components.classes["@mozilla.org/file/directory_service;1"].getService( Components.interfaces.nsIProperties );
            var file = dirs.get( "Home", Components.interfaces.nsIFile );
            file.append( ".twitsecret" );
            file.append( filename );
            return file;
        },

        readFile: function( filename ) {
            var data = "";
            var file = ___twitsecret.backend.getFile( filename );
            var fstream = Components.classes["@mozilla.org/network/file-input-stream;1"].createInstance( Components.interfaces.nsIFileInputStream );
            var cstream = Components.classes["@mozilla.org/intl/converter-input-stream;1"].createInstance( Components.interfaces.nsIConverterInputStream );
            fstream.init( file, -1, 0, 0 );
            cstream.init( fstream, "UTF-8", 0, 0 );
            var str = {};
            var read = 0;
            do {
                read = cstream.readString( 0xffffffff, str );
                data += str.value;
            } while (read != 0);
            cstream.close();
            return data;
        },

        writeFile: function( filename, msg ) {
            var file = ___twitsecret.backend.getFile( filename );
            var fstream = Components.classes["@mozilla.org/network/file-output-stream;1"].createInstance( Components.interfaces.nsIFileOutputStream );
            var cstream = Components.classes["@mozilla.org/intl/converter-output-stream;1"].createInstance( Components.interfaces.nsIConverterOutputStream );
            fstream.init( file, 0x02 | 0x08 | 0x20, 0600, 0 ); // write, create, truncate
            cstream.init( fstream, "UTF-8", 0, 0 );
            cstream.writeString( msg );
            cstream.close();
        },

        hexToBin: function( hex ) {
            var binary = "";
            for (var i = 0; i < hex.length; i += 2) {
                var val = parseInt( hex.substr( i, 2 ), 16 );
                if (val == 0x22 || val == 0x3C || val == 0x3E) {    // twitter doesn't allow these in bio
                    val += 0x100;
                }
                binary += String.fromCharCode( val );
            }
            return binary;
        },

        binToHex: function( binary ) {
            var hex = "";
            for (var i = 0; i < binary.length; i++) {
                var val = binary.charCodeAt( i );
                if (val > 0x100) {
                    val -= 0x100;
                }
                var pair = new Number( val ).toString( 16 );
                hex += (pair.length < 2 ? "0" + pair : pair);
            }
            return hex;
        },

        init: function( userId ) {
            var process = ___twitsecret.backend.getProcess();
            var args = new Array();
            args.push( "init" );
            args.push( userId );
            args.push( ___twitsecret.password );
            process.run( true, args, args.length );
            if (process.exitValue != 0) {
                return null;
            }

            var pubkey = ___twitsecret.backend.readFile( userId + ".pub" );
            var ix = pubkey.indexOf( "(n #" ) + 4;
            var endIx = pubkey.indexOf( "#", ix );
            return ___twitsecret.backend.hexToBin( pubkey.substring( ix, endIx ) );
        },

        add: function( userId, pubkey ) {
            var process = ___twitsecret.backend.getProcess();
            var args = new Array();
            args.push( "add" );
            args.push( userId );
            args.push( ___twitsecret.backend.binToHex( pubkey ) );
            process.run( true, args, args.length );
            return (process.exitValue == 0);
        },

        encrypt: function( msg, recipients ) {
            if (msg != null) {
                ___twitsecret.backend.writeFile( "twitsecret.plain", msg );
            }
            var process = ___twitsecret.backend.getProcess();
            var args = new Array();
            args.push( "enc" );
            args = args.concat( recipients );
            process.run( true, args, args.length );
            if (process.exitValue != 0) {
                return null;
            }
            return ___twitsecret.backend.readFile( "twitsecret.cipher" );
        },

        decrypt: function( msg, userId ) {
            if (msg != null) {
                ___twitsecret.backend.writeFile( "twitsecret.cipher", msg );
            }
            var process = ___twitsecret.backend.getProcess();
            var args = new Array();
            args.push( "dec" );
            args.push( userId );
            args.push( ___twitsecret.password );
            process.run( true, args, args.length );
            if (process.exitValue != 0) {
                return null;
            }
            return ___twitsecret.backend.readFile( "twitsecret.plain" );
        },
    },
}

if (window.toString() == "[object ChromeWindow]") {
    window.addEventListener( 'load', ___twitsecret.init, false );
}
