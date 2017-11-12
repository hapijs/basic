'use strict';

// Load modules

const Boom = require('boom');
const Code = require('code');
const Hapi = require('hapi');
const Lab = require('lab');


// Declare internals

const internals = {};


// Test shortcuts

const lab = exports.lab = Lab.script();
const it = lab.it;
const expect = Code.expect;


it('returns a reply on successful auth', async () => {

    const server = Hapi.server();
    await server.register(require('../'));
    server.auth.strategy('default', 'basic', { validate: internals.user });

    server.route({
        method: 'POST',
        path: '/',
        handler: function (request, h) {

            return 'ok';
        },
        options: {
            auth: 'default'
        }
    });

    const request = { method: 'POST', url: '/', headers: { authorization: internals.header('john', '123:45') } };
    const res = await server.inject(request);

    expect(res.result).to.equal('ok');
});

it('returns an error on wrong scheme', async () => {

    const server = Hapi.server();
    await server.register(require('../'));
    server.auth.strategy('default', 'basic', { validate: internals.user });

    server.route({
        method: 'POST',
        path: '/',
        handler: function (request, h) {

            return 'ok';
        },
        options: {
            auth: 'default'
        }
    });

    const request = { method: 'POST', url: '/', headers: { authorization: 'Steve something' } };
    const res = await server.inject(request);

    expect(res.statusCode).to.equal(401);
});

it('returns a reply on successful double auth', async () => {

    const handler = async function (request, h) {

        const options = { method: 'POST', url: '/inner', headers: { authorization: internals.header('john', '123:45') }, credentials: request.auth.credentials };
        const res = await server.inject(options);

        return res.result;
    };

    const server = Hapi.server();
    await server.register(require('../'));

    server.auth.strategy('default', 'basic', { validate: internals.user });

    server.route({ method: 'POST', path: '/', handler });
    server.route({
        method: 'POST',
        path: '/inner',
        handler: function (request, h) {

            return 'ok';
        },
        options: {
            auth: 'default'
        }
    });

    const request = { method: 'POST', url: '/', headers: { authorization: internals.header('john', '123:45') } };

    const res = await server.inject(request);

    expect(res.result).to.equal('ok');
});

it('returns a reply on failed optional auth', async () => {

    const server = Hapi.server();

    await server.register(require('../'));

    server.auth.strategy('default', 'basic', { validate: internals.user });
    server.route({
        method: 'POST',
        path: '/',
        handler: function (request, h) {

            return 'ok';
        },
        options: {
            auth: {
                strategy: 'default',
                mode: 'optional'
            }
        }
    });

    const request = { method: 'POST', url: '/' };

    const res = await server.inject(request);
    expect(res.result).to.equal('ok');
});

it('returns an error on bad password', async () => {

    const server = Hapi.server();
    await server.register(require('../'));

    server.auth.strategy('default', 'basic', { validate: internals.user });
    server.route({
        method: 'POST',
        path: '/',
        handler: function (request, h) {

            return 'ok';
        },
        options: {
            auth: 'default'
        }
    });

    const request = { method: 'POST', url: '/', headers: { authorization: internals.header('john', 'abcd') } };

    const res = await server.inject(request);
    expect(res.statusCode).to.equal(401);
});

it('returns an error on bad header format', async () => {

    const server = Hapi.server();
    await server.register(require('../'));

    server.auth.strategy('default', 'basic', { validate: internals.user });
    server.route({
        method: 'POST',
        path: '/',
        handler: function (request, h) {

            return 'ok';
        },
        options: {
            auth: 'default'
        }
    });

    const request = { method: 'POST', url: '/', headers: { authorization: 'basic' } };

    const res = await server.inject(request);

    expect(res.result).to.exist();
    expect(res.statusCode).to.equal(400);
    expect(res.result.isMissing).to.equal(undefined);
});

it('returns an error on bad header internal syntax', async () => {

    const server = Hapi.server();
    await server.register(require('../'));

    server.auth.strategy('default', 'basic', { validate: internals.user });
    server.route({
        method: 'POST',
        path: '/',
        handler: function (request, h) {

            return 'ok';
        },
        options: {
            auth: 'default'
        }
    });

    const request = { method: 'POST', url: '/', headers: { authorization: 'basic 123' } };

    const res = await server.inject(request);

    expect(res.result).to.exist();
    expect(res.statusCode).to.equal(400);
    expect(res.result.isMissing).to.equal(undefined);
});

it('returns an error on missing username', async () => {

    const server = Hapi.server();
    await server.register(require('../'));

    server.auth.strategy('default', 'basic', { validate: internals.user });
    server.route({
        method: 'POST',
        path: '/',
        handler: function (request, h) {

            return 'ok';
        },
        options: {
            auth: 'default'
        }
    });

    const request = { method: 'POST', url: '/', headers: { authorization: internals.header('', '') } };

    const res = await server.inject(request);

    expect(res.result).to.exist();
    expect(res.statusCode).to.equal(401);
});

it('allow missing username', async () => {

    const server = Hapi.server();
    await server.register(require('../'));

    server.auth.strategy('default', 'basic', {
        validate: () => ({ isValid: true, credentials: {} }),
        allowEmptyUsername: true
    });

    server.route({
        method: 'GET',
        path: '/',
        handler: function (request, h) {

            return 'ok';
        },
        options: {
            auth: 'default'
        }
    });

    const res = await server.inject({ method: 'GET', url: '/', headers: { authorization: internals.header('', 'abcd') } });

    expect(res.statusCode).to.equal(200);
});

it('returns an error on unknown user', async () => {

    const server = Hapi.server();
    await server.register(require('../'));

    server.auth.strategy('default', 'basic', { validate: internals.user });
    server.route({
        method: 'POST',
        path: '/',
        handler: function (request, h) {

            return 'ok';
        },
        options: {
            auth: 'default'
        }
    });

    const request = { method: 'POST', url: '/', headers: { authorization: internals.header('doe', '123:45') } };
    const res = await server.inject(request);

    expect(res.result).to.exist();
    expect(res.statusCode).to.equal(401);
});

it('replies with thrown custom error', async () => {

    const server = Hapi.server({ debug: false });
    await server.register(require('../'));

    server.auth.strategy('default', 'basic', { validate: internals.user });
    server.route({
        method: 'POST',
        path: '/',
        handler: function (request, h) {

            return 'ok';
        },
        options: {
            auth: 'default'
        }
    });

    const request = { method: 'POST', url: '/', headers: { authorization: internals.header('jane', '123:45') } };

    const res = await server.inject(request);

    expect(res.result).to.exist();
    expect(res.result.message).to.equal('Some other problem');
    expect(res.statusCode).to.equal(400);
});

it('replies with takeover response', async () => {

    const server = Hapi.server({ debug: false });
    await server.register(require('../'));

    server.auth.strategy('default', 'basic', { validate: internals.user });
    server.route({
        method: 'POST',
        path: '/',
        handler: function (request, h) {

            return 'ok';
        },
        options: {
            auth: 'default'
        }
    });

    const request = { method: 'POST', url: '/', headers: { authorization: internals.header('bob', '123:45') } };

    const res = await server.inject(request);

    expect(res.statusCode).to.equal(302);
    expect(res.headers.location).to.equal('https://hapijs.com');
});

it('returns an error on non-object credentials error', async () => {

    const server = Hapi.server({ debug: false });
    await server.register(require('../'));

    server.auth.strategy('default', 'basic', { validate: internals.user });
    server.route({
        method: 'POST',
        path: '/',
        handler: function (request, h) {

            return 'ok';
        },
        options: {
            auth: 'default'
        }
    });

    const request = { method: 'POST', url: '/', headers: { authorization: internals.header('invalid1', '123:45') } };

    const res = await server.inject(request);

    expect(res.result).to.exist();
    expect(res.statusCode).to.equal(500);
});

it('returns an error on missing credentials error', async () => {

    const server = Hapi.server({ debug: false });
    await server.register(require('../'));

    server.auth.strategy('default', 'basic', { validate: internals.user });
    server.route({
        method: 'POST',
        path: '/',
        handler: function (request, h) {

            return 'ok';
        },
        options: {
            auth: 'default'
        }
    });

    const request = { method: 'POST', url: '/', headers: { authorization: internals.header('invalid2', '123:45') } };

    const res = await server.inject(request);

    expect(res.result).to.exist();
    expect(res.statusCode).to.equal(500);
});

it('returns an error on insufficient scope', async () => {

    const server = Hapi.server();
    await server.register(require('../'));

    server.auth.strategy('default', 'basic', { validate: internals.user });
    server.route({
        method: 'POST',
        path: '/',
        handler: function (request, h) {

            return 'ok';
        },
        options: {
            auth: {
                strategy: 'default',
                scope: 'x'
            }
        }
    });

    const request = { method: 'POST', url: '/', headers: { authorization: internals.header('john', '123:45') } };

    const res = await server.inject(request);

    expect(res.result).to.exist();
    expect(res.statusCode).to.equal(403);
});

it('returns an error on insufficient scope specified as an array', async () => {

    const server = Hapi.server();
    await server.register(require('../'));

    server.auth.strategy('default', 'basic', { validate: internals.user });

    server.route({
        method: 'POST',
        path: '/',
        handler: function (request, h) {

            return 'ok';
        },
        options: {
            auth: {
                strategy: 'default',
                scope: ['x', 'y']
            }
        }
    });

    const request = { method: 'POST', url: '/', headers: { authorization: internals.header('john', '123:45') } };

    const res = await server.inject(request);

    expect(res.result).to.exist();
    expect(res.statusCode).to.equal(403);
});

it('authenticates scope specified as an array', async () => {

    const server = Hapi.server();
    await server.register(require('../'));

    server.auth.strategy('default', 'basic', { validate: internals.user });
    server.route({
        method: 'POST',
        path: '/',
        handler: function (request, h) {

            return 'ok';
        },
        options: {
            auth: {
                strategy: 'default',
                scope: ['x', 'y', 'a']
            }
        }
    });

    const request = { method: 'POST', url: '/', headers: { authorization: internals.header('john', '123:45') } };

    const res = await server.inject(request);

    expect(res.result).to.exist();
    expect(res.statusCode).to.equal(200);
});

it('should ask for credentials if server has one default strategy', async () => {

    const server = Hapi.server();
    await server.register(require('../'));


    server.auth.strategy('default', 'basic', { validate: internals.user });
    server.route({
        path: '/',
        method: 'GET',
        options: {
            auth: 'default',
            handler: function (request, h) {

                return 'ok';
            }
        }
    });

    const validOptions = { method: 'GET', url: '/', headers: { authorization: internals.header('john', '123:45') } };
    const res1 = await server.inject(validOptions);

    expect(res1.result).to.exist();
    expect(res1.statusCode).to.equal(200);

    const res2 = await server.inject('/');

    expect(res2.result).to.exist();
    expect(res2.statusCode).to.equal(401);
});


it('cannot add a route that has payload validation required', async () => {

    const server = Hapi.server();
    await server.register(require('../'));

    server.auth.strategy('default', 'basic', { validate: internals.user });

    const fn = function () {

        server.route({
            method: 'POST',
            path: '/',
            handler: function (request, h) {

                return 'ok';
            },
            options: {
                auth: {
                    strategy: 'default',
                    mode: 'required',
                    payload: 'required'
                }
            }
        });
    };

    expect(fn).to.throw('Payload validation can only be required when all strategies support it in /');
});

it('cannot add a route that has payload validation as optional', async () => {

    const server = Hapi.server();
    await server.register(require('../'));

    server.auth.strategy('default', 'basic', { validate: internals.user });

    const fn = function () {

        server.route({
            method: 'POST',
            path: '/',
            handler: function (request, h) {

                return 'ok';
            },
            options: {
                auth: {
                    strategy: 'default',
                    mode: 'required',
                    payload: 'optional'
                }
            }
        });
    };

    expect(fn).to.throw('Payload authentication requires at least one strategy with payload support in /');
});

it('can add a route that has payload validation as none', async () => {

    const server = Hapi.server();
    await server.register(require('../'));

    server.auth.strategy('default', 'basic', { validate: internals.user });

    const fn = function () {

        server.route({
            method: 'POST',
            path: '/',
            handler: function (request, h) {

                return 'ok';
            },
            options: {
                auth: {
                    strategy: 'default',
                    mode: 'required',
                    payload: false
                }
            }
        });
    };

    expect(fn).to.not.throw();
});

it('includes additional attributes in WWW-Authenticate header', async () => {

    const server = Hapi.server();
    await server.register(require('../'));

    server.auth.strategy('default', 'basic', {
        validate: internals.user,
        unauthorizedAttributes: { realm: 'hapi' }
    });

    server.route({
        method: 'POST',
        path: '/',
        handler: function (request, h) {

            return 'ok';
        },
        options: {
            auth: 'default'
        }
    });

    const request = { method: 'POST', url: '/' };

    const res = await server.inject(request);

    const wwwAuth = 'www-authenticate';
    expect(res.headers).to.include(wwwAuth);
    expect(res.headers[wwwAuth]).to.equal('Basic realm=\"hapi\"');
});


internals.header = function (username, password) {

    return 'Basic ' + (new Buffer(username + ':' + password, 'utf8')).toString('base64');
};


internals.user = async function (request, username, password, h) {

    if (username === 'john') {
        return await Promise.resolve({
            isValid: password === '123:45',
            credentials: {
                user: 'john',
                scope: ['a'],
                tos: '1.0.0'
            }
        });
    }

    if (username === 'jane') {
        throw Boom.badRequest('Some other problem');
    }

    if (username === 'bob') {
        return await Promise.resolve({ takeover: h.redirect('https://hapijs.com') });
    }

    if (username === 'invalid1') {
        return await Promise.resolve({
            isValid: true,
            credentials: 'bad'
        });
    }

    if (username === 'invalid2') {
        return await Promise.resolve({
            isValid: true,
            credentials: null
        });
    }

    return { isValid: false };
};
