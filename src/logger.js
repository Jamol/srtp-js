/**
 * @fileOverview logger
 * @author <a href="jamol@live.com">Fengping Bao</a>
 * @version 1.0.0
 */
;(function (SrtpJS, undefined) {
    var exports = SrtpJS;
    var logger = exports.logger || {};
    var getsettest = {};
    Object.defineProperty(getsettest, 'test', {
        get: function() {
            return 'test';
        }});
    var hasGetSet = getsettest.test == 'test';

    var _console = window.console || {};
    var _methods = ['log', 'info', 'warn', 'error', 'debug'];
    for (var i = 0, len = _methods.length; i < len; i++) {
        (function(method){
            var fn = _console[method];
            if (null == fn) {
                if(logger.log)
                    logger[method] = logger.log;
                else    
                    logger[method] = function(){};
                return;
            }
            
            var fDate = function(iD){
                if(iD < 10 && iD >= 0){
                    return '0' + iD;
                }else{
                    return iD;
                }
            };

            var getTime = function(method){
                var now = new Date();
                var prefix = "[" + fDate(now.getMonth() + 1) + "/" + fDate(now.getDate());
                prefix += " " + fDate(now.getHours()) + ":" + fDate(now.getMinutes()) + ":" + fDate(now.getSeconds()) + "." + fDate(now.getMilliseconds()) + "]";
                prefix += "[" + method + "]";    
                return prefix;
            };
            if (Function.prototype.bind && hasGetSet) {
                Object.defineProperty(logger, method, {
                    get: function() {
                        return Function.prototype.bind.call(_console[method], _console, getTime(method))
                        }
                    });
            }else{
                //Only IE7/8 goes here.
                logger[method] = function() { 
                    Function.prototype.apply.call(_console[method], _console, arguments);
                };
            }
            
        }(_methods[i]));
    }

    exports.logger = logger;
    return logger;
}(SrtpJS));
