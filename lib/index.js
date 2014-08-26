// Load modules

var Boom = require('boom');
var Hoek = require('hoek');


// Declare internals

var internals = {};

internals.defaults = {
    strategy: {
        name: 'basic',
        mode: false,
        options: {}
    }
};

exports.register = function (plugin, options, next) {

    plugin.auth.scheme('basic', internals.implementation);

    if (options.strategy) {
        var strategy = Hoek.applyToDefaults(internals.defaults.strategy, options.strategy);
        plugin.auth.strategy(strategy.name, 'basic', strategy.mode, strategy.options);
    }

    next();
};


exports.register.attributes = {
    pkg: require('../package.json')
};


internals.implementation = function (server, options) {
    
    Hoek.assert(options, 'Missing basic auth strategy options');
    Hoek.assert(typeof options.validateFunc === 'function', 'options.validateFunc must be a valid function in basic scheme');

    var settings = Hoek.clone(options);

    var scheme = {
        authenticate: function (request, reply) {

            var req = request.raw.req;
            var authorization = req.headers.authorization;
            if (!authorization) {
                return reply(Boom.unauthorized(null, 'Basic'));
            }

            var parts = authorization.split(/\s+/);

            if (parts[0].toLowerCase() !== 'basic') {
                return reply(Boom.unauthorized(null, 'Basic'));
            }

            if (parts.length !== 2) {
                return reply(Boom.badRequest('Bad HTTP authentication header format', 'Basic'));
            }

            var credentialsPart = new Buffer(parts[1], 'base64').toString();
            var sep = credentialsPart.indexOf(':');
            if (sep === -1) {
                return reply(Boom.badRequest('Bad header internal syntax', 'Basic'));
            }

            var username = credentialsPart.slice(0, sep);
            var password = credentialsPart.slice(sep + 1);

            if (!username && !settings.allowEmptyUsername) {
                return reply(Boom.unauthorized('HTTP authentication header missing username', 'Basic'));
            }

            settings.validateFunc(username, password, function (err, isValid, credentials) {

                credentials = credentials || null;

                if (err) {
                    return reply(err, { credentials: credentials, log: { tags: ['auth', 'basic'], data: err } });
                }

                if (!isValid) {
                    return reply(Boom.unauthorized('Bad username or password', 'Basic'), { credentials: credentials });
                }

                if (!credentials ||
                    typeof credentials !== 'object') {

                    return reply(Boom.badImplementation('Bad credentials object received for Basic auth validation'), { log: { tags: 'credentials' } });
                }

                // Authenticated

                return reply(null, { credentials: credentials });
            });
        }
    };

    return scheme;
};


