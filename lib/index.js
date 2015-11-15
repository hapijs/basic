'use strict';

// Load modules

const Boom = require('boom');
const Hoek = require('hoek');


// Declare internals

const internals = {};


exports.register = function (plugin, options, next) {

    plugin.auth.scheme('basic', internals.implementation);
    next();
};


exports.register.attributes = {
    pkg: require('../package.json')
};


internals.implementation = function (server, options) {

    Hoek.assert(options, 'Missing basic auth strategy options');
    Hoek.assert(typeof options.validateFunc === 'function', 'options.validateFunc must be a valid function in basic scheme');

    const settings = Hoek.clone(options);

    const scheme = {
        authenticate: function (request, reply) {

            const req = request.raw.req;
            const authorization = req.headers.authorization;
            if (!authorization) {
                return reply(Boom.unauthorized(null, 'Basic', settings.unauthorizedAttributes));
            }

            const parts = authorization.split(/\s+/);

            if (parts[0].toLowerCase() !== 'basic') {
                return reply(Boom.unauthorized(null, 'Basic', settings.unauthorizedAttributes));
            }

            if (parts.length !== 2) {
                return reply(Boom.badRequest('Bad HTTP authentication header format', 'Basic'));
            }

            const credentialsPart = new Buffer(parts[1], 'base64').toString();
            const sep = credentialsPart.indexOf(':');
            if (sep === -1) {
                return reply(Boom.badRequest('Bad header internal syntax', 'Basic'));
            }

            const username = credentialsPart.slice(0, sep);
            const password = credentialsPart.slice(sep + 1);

            if (!username && !settings.allowEmptyUsername) {
                return reply(Boom.unauthorized('HTTP authentication header missing username', 'Basic', settings.unauthorizedAttributes));
            }

            settings.validateFunc(request, username, password, (err, isValid, credentials) => {

                credentials = credentials || null;

                if (err) {
                    return reply(err, null, { credentials: credentials });
                }

                if (!isValid) {
                    return reply(Boom.unauthorized('Bad username or password', 'Basic', settings.unauthorizedAttributes), null, { credentials: credentials });
                }

                if (!credentials ||
                    typeof credentials !== 'object') {

                    return reply(Boom.badImplementation('Bad credentials object received for Basic auth validation'));
                }

                // Authenticated

                return reply.continue({ credentials: credentials });
            });
        }
    };

    return scheme;
};
