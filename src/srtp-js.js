/**
 * @fileOverview SrtpJS
 * @author <a href="jamol@live.com">Fengping Bao</a>
 * @version 1.0.0
 */
var SrtpJS = null;
(function (window, undefined) {
    SrtpJS = {
        extend: function (base, copy, override) {
            for (var name in copy) {
                if (copy[name] == undefined || (override === false && base.hasOwnProperty(name)))
                    continue;
                base[name] = copy[name];
            }
            return base;
        }
    };
    return SrtpJS;
})(window);
