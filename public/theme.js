'use strict';
/* Theme switcher: light | dark | system. Choice is remembered in localStorage. */
(function () {
    var KEY = 'strongroom-theme';
    var mq = window.matchMedia('(prefers-color-scheme: dark)');
    function stored() {
        try { return localStorage.getItem(KEY) || 'system'; } catch (e) { return 'system'; }
    }
    function apply(mode) {
        var dark = mode === 'dark' || (mode === 'system' && mq.matches);
        document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
    }
    window.StrongroomTheme = {
        get: stored,
        set: function (mode) {
            try { localStorage.setItem(KEY, mode); } catch (e) { /* private mode: still applies for this visit */ }
            apply(mode);
        },
    };
    apply(stored());
    mq.addEventListener('change', function () { if (stored() === 'system') apply('system'); });
})();