___twitsecret = {
    enabled: true,

    init: function() {
        var appcontent = document.getElementById( 'appcontent' );
        if (! appcontent) {
            ___twitsecret.logError( 'Unable to obtain appcontent' );
            return false;
        }
        appcontent.addEventListener( "DOMContentLoaded", ___twitsecret.docload, true );
        return true;
    },

    uninit: function() {
        var appcontent = document.getElementById( 'appcontent' );
        if (! appcontent) {
            ___twitsecret.logError( 'Unable to obtain appcontent' );
            return false;
        }
        appcontent.removeEventListener( "DOMContentLoaded", ___twitsecret.docload, true );
        return true;
    },

    logError: function( errmsg ) {
        Components.utils.reportError( "TwitSecret: " + errmsg );
    },

    toggle: function() {
        if (! ___twitsecret.enabled) {
            if (___twitsecret.init()) {
                ___twitsecret.enabled = true;
                ___twitsecret.updateStatus();
            }
        } else if (___twitsecret.uninit()) {
            ___twitsecret.enabled = false;
            ___twitsecret.updateStatus();
        }
    },

    updateStatus: function() {
        document.getElementById( 'twitsecret-statusbar-panel' ).setAttribute( 'label', 'TwitSecret is ' + (___twitsecret.enabled ? 'ON' : 'OFF') );
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
    }
}

window.addEventListener( 'load', ___twitsecret.init, false );
