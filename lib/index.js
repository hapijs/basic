'use strict';

// Load modules

const Boom = require('boom');
const Hoek = require('hoek');


// Declare internals

const internals = {};


exports.plugin = {
    pkg: require('../package.json'),
    register: function (server) {

        server.auth.scheme('basic', internals.implementation);
    }
};


internals.implementation = function (server, options) {

    Hoek.assert(options, 'Missing basic auth strategy options');
    Hoek.assert(typeof options.validate === 'function', 'options.validate must be a valid function in basic scheme');

    const settings = Hoek.clone(options);

    const scheme = {
        authenticate: async function (request, h) {

            const authorization = request.headers.authorization;

            if (!authorization) {
                return h.unauthenticated(Boom.unauthorized(null, 'Basic', settings.unauthorizedAttributes));
            }

            const parts = authorization.split(/\s+/);

            if (parts[0].toLowerCase() !== 'basic') {
                return h.unauthenticated(Boom.unauthorized(null, 'Basic', settings.unauthorizedAttributes));
            }

            if (parts.length !== 2) {
                return h.unauthenticated(Boom.badRequest('Bad HTTP authentication header format', 'Basic'));
            }

            const credentialsPart = Buffer.from(parts[1], 'base64').toString();
            const sep = credentialsPart.indexOf(':');
            if (sep === -1) {
                return h.unauthenticated(Boom.badRequest('Bad header internal syntax', 'Basic'));
            }

            const username = credentialsPart.slice(0, sep);
            const password = credentialsPart.slice(sep + 1);

            if (!username &&
                !settings.allowEmptyUsername) {

                return h.unauthenticated(Boom.unauthorized('HTTP authentication header missing username', 'Basic', settings.unauthorizedAttributes));
            }

            try {
                const { isValid, credentials, takeover } = await settings.validate(request, username, password, h);

                if (takeover !== undefined) {
                    return h.response(takeover).takeover();
                }

                if (!isValid) {
                    return h.unauthenticated(Boom.unauthorized('Bad username or password', 'Basic', settings.unauthorizedAttributes), credentials ? { credentials } : null);
                }

                if (!credentials ||
                    typeof credentials !== 'object') {

                    return h.unauthenticated(Boom.badImplementation('Bad credentials object received for Basic auth validation'));
                }

                return h.authenticated({ credentials });
            }
            catch (err) {
                return h.unauthenticated(err);
            }
        }
    };

    return scheme;
};
