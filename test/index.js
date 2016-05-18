'use strict';

// Load modules

const Code = require('code');
const Hapi = require('hapi');
const Lab = require('lab');


// Declare internals

const internals = {};


// Test shortcuts

const lab = exports.lab = Lab.script();
const it = lab.it;
const expect = Code.expect;


it('returns a reply on successful auth', (done) => {

    const server = new Hapi.Server();
    server.connection();
    server.register(require('../'), (err) => {

        expect(err).to.not.exist();
        server.auth.strategy('default', 'basic', 'required', { validateFunc: internals.user });
        server.route({
            method: 'POST',
            path: '/',
            handler: function (request, reply) {

                return reply('ok');
            },
            config: {
                auth: 'default'
            }
        });

        const request = { method: 'POST', url: '/', headers: { authorization: internals.header('john', '123:45') } };

        server.inject(request, (res) => {

            expect(res.result).to.equal('ok');
            done();
        });
    });
});

it('returns an error on wrong scheme', (done) => {

    const server = new Hapi.Server();
    server.connection();
    server.register(require('../'), (err) => {

        expect(err).to.not.exist();
        server.auth.strategy('default', 'basic', 'required', { validateFunc: internals.user });
        server.route({
            method: 'POST',
            path: '/',
            handler: function (request, reply) {

                return reply('ok');
            },
            config: {
                auth: 'default'
            }
        });

        const request = { method: 'POST', url: '/', headers: { authorization: 'Steve something' } };

        server.inject(request, (res) => {

            expect(res.statusCode).to.equal(401);
            done();
        });
    });
});

it('returns a reply on successful double auth', (done) => {

    const handler = function (request, reply) {

        const options = { method: 'POST', url: '/inner', headers: { authorization: internals.header('john', '123:45') }, credentials: request.auth.credentials };
        server.inject(options, (res) => {

            return reply(res.result);
        });
    };

    const server = new Hapi.Server();
    server.connection();
    server.register(require('../'), (err) => {

        expect(err).to.not.exist();
        server.auth.strategy('default', 'basic', 'required', { validateFunc: internals.user });
        server.route({ method: 'POST', path: '/', handler: handler });
        server.route({
            method: 'POST',
            path: '/inner',
            handler: function (request, reply) {

                return reply('ok');
            },
            config: {
                auth: 'default'
            }
        });

        const request = { method: 'POST', url: '/', headers: { authorization: internals.header('john', '123:45') } };

        server.inject(request, (res) => {

            expect(res.result).to.equal('ok');
            done();
        });
    });
});

it('returns a reply on failed optional auth', (done) => {

    const server = new Hapi.Server();
    server.connection();
    server.register(require('../'), (err) => {

        expect(err).to.not.exist();
        server.auth.strategy('default', 'basic', 'required', { validateFunc: internals.user });
        server.route({
            method: 'POST',
            path: '/',
            handler: function (request, reply) {

                return reply('ok');
            },
            config: {
                auth: {
                    mode: 'optional'
                }
            }
        });

        const request = { method: 'POST', url: '/' };

        server.inject(request, (res) => {

            expect(res.result).to.equal('ok');
            done();
        });
    });
});

it('returns an error on bad password', (done) => {

    const server = new Hapi.Server();
    server.connection();
    server.register(require('../'), (err) => {

        expect(err).to.not.exist();
        server.auth.strategy('default', 'basic', 'required', { validateFunc: internals.user });
        server.route({
            method: 'POST',
            path: '/',
            handler: function (request, reply) {

                return reply('ok');
            },
            config: {
                auth: 'default'
            }
        });

        const request = { method: 'POST', url: '/', headers: { authorization: internals.header('john', 'abcd') } };

        server.inject(request, (res) => {

            expect(res.statusCode).to.equal(401);
            done();
        });
    });
});

it('returns an error on bad header format', (done) => {

    const server = new Hapi.Server();
    server.connection();
    server.register(require('../'), (err) => {

        expect(err).to.not.exist();
        server.auth.strategy('default', 'basic', 'required', { validateFunc: internals.user });
        server.route({
            method: 'POST',
            path: '/',
            handler: function (request, reply) {

                return reply('ok');
            },
            config: {
                auth: 'default'
            }
        });

        const request = { method: 'POST', url: '/', headers: { authorization: 'basic' } };

        server.inject(request, (res) => {

            expect(res.result).to.exist();
            expect(res.statusCode).to.equal(400);
            expect(res.result.isMissing).to.equal(undefined);
            done();
        });
    });
});

it('returns an error on bad header internal syntax', (done) => {

    const server = new Hapi.Server();
    server.connection();
    server.register(require('../'), (err) => {

        expect(err).to.not.exist();
        server.auth.strategy('default', 'basic', 'required', { validateFunc: internals.user });
        server.route({
            method: 'POST',
            path: '/',
            handler: function (request, reply) {

                return reply('ok');
            },
            config: {
                auth: 'default'
            }
        });

        const request = { method: 'POST', url: '/', headers: { authorization: 'basic 123' } };

        server.inject(request, (res) => {

            expect(res.result).to.exist();
            expect(res.statusCode).to.equal(400);
            expect(res.result.isMissing).to.equal(undefined);
            done();
        });
    });
});

it('returns an error on missing username', (done) => {

    const server = new Hapi.Server();
    server.connection();
    server.register(require('../'), (err) => {

        expect(err).to.not.exist();
        server.auth.strategy('default', 'basic', 'required', { validateFunc: internals.user });
        server.route({
            method: 'POST',
            path: '/',
            handler: function (request, reply) {

                return reply('ok');
            },
            config: {
                auth: 'default'
            }
        });

        const request = { method: 'POST', url: '/', headers: { authorization: internals.header('', '') } };

        server.inject(request, (res) => {

            expect(res.result).to.exist();
            expect(res.statusCode).to.equal(401);
            done();
        });
    });
});

it('allow missing username', (done) => {

    const server = new Hapi.Server();
    server.connection();
    server.register(require('../'), (err) => {

        expect(err).to.not.exist();

        server.auth.strategy('default', 'basic', {
            validateFunc: function (request, username, password, callback) {

                callback(null, true, {});
            },
            allowEmptyUsername: true
        });

        server.route({
            method: 'GET',
            path: '/',
            handler: function (request, reply) {

                return reply('ok');
            },
            config: {
                auth: 'default'
            }
        });

        server.inject({ method: 'GET', url: '/', headers: { authorization: internals.header('', 'abcd') } }, (res) => {

            expect(res.statusCode).to.equal(200);
            done();
        });
    });
});

it('returns an error on unknown user', (done) => {

    const server = new Hapi.Server();
    server.connection();
    server.register(require('../'), (err) => {

        expect(err).to.not.exist();
        server.auth.strategy('default', 'basic', 'required', { validateFunc: internals.user });
        server.route({
            method: 'POST',
            path: '/',
            handler: function (request, reply) {

                return reply('ok');
            },
            config: {
                auth: 'default'
            }
        });

        const request = { method: 'POST', url: '/', headers: { authorization: internals.header('doe', '123:45') } };

        server.inject(request, (res) => {

            expect(res.result).to.exist();
            expect(res.statusCode).to.equal(401);
            done();
        });
    });
});

it('returns an error on internal user lookup error', (done) => {

    const server = new Hapi.Server({ debug: false });
    server.connection();
    server.register(require('../'), (err) => {

        expect(err).to.not.exist();
        server.auth.strategy('default', 'basic', 'required', { validateFunc: internals.user });
        server.route({
            method: 'POST',
            path: '/',
            handler: function (request, reply) {

                return reply('ok');
            },
            config: {
                auth: 'default'
            }
        });

        const request = { method: 'POST', url: '/', headers: { authorization: internals.header('jane', '123:45') } };

        server.inject(request, (res) => {

            expect(res.result).to.exist();
            expect(res.statusCode).to.equal(500);
            done();
        });
    });
});

it('returns an error on non-object credentials error', (done) => {

    const server = new Hapi.Server({ debug: false });
    server.connection();
    server.register(require('../'), (err) => {

        expect(err).to.not.exist();
        server.auth.strategy('default', 'basic', 'required', { validateFunc: internals.user });
        server.route({
            method: 'POST',
            path: '/',
            handler: function (request, reply) {

                return reply('ok');
            },
            config: {
                auth: 'default'
            }
        });

        const request = { method: 'POST', url: '/', headers: { authorization: internals.header('invalid1', '123:45') } };

        server.inject(request, (res) => {

            expect(res.result).to.exist();
            expect(res.statusCode).to.equal(500);
            done();
        });
    });
});

it('returns an error on missing credentials error', (done) => {

    const server = new Hapi.Server({ debug: false });
    server.connection();
    server.register(require('../'), (err) => {

        expect(err).to.not.exist();
        server.auth.strategy('default', 'basic', 'required', { validateFunc: internals.user });
        server.route({
            method: 'POST',
            path: '/',
            handler: function (request, reply) {

                return reply('ok');
            },
            config: {
                auth: 'default'
            }
        });

        const request = { method: 'POST', url: '/', headers: { authorization: internals.header('invalid2', '123:45') } };

        server.inject(request, (res) => {

            expect(res.result).to.exist();
            expect(res.statusCode).to.equal(500);
            done();
        });
    });
});

it('returns an error on insufficient scope', (done) => {

    const server = new Hapi.Server();
    server.connection();
    server.register(require('../'), (err) => {

        expect(err).to.not.exist();
        server.auth.strategy('default', 'basic', 'required', { validateFunc: internals.user });
        server.route({
            method: 'POST',
            path: '/',
            handler: function (request, reply) {

                return reply('ok');
            },
            config: {
                auth: {
                    scope: 'x'
                }
            }
        });

        const request = { method: 'POST', url: '/', headers: { authorization: internals.header('john', '123:45') } };

        server.inject(request, (res) => {

            expect(res.result).to.exist();
            expect(res.statusCode).to.equal(403);
            done();
        });
    });
});

it('returns an error on insufficient scope specified as an array', (done) => {

    const server = new Hapi.Server();
    server.connection();
    server.register(require('../'), (err) => {

        expect(err).to.not.exist();
        server.auth.strategy('default', 'basic', 'required', { validateFunc: internals.user });
        server.route({
            method: 'POST',
            path: '/',
            handler: function (request, reply) {

                return reply('ok');
            },
            config: {
                auth: {
                    scope: ['x', 'y']
                }
            }
        });

        const request = { method: 'POST', url: '/', headers: { authorization: internals.header('john', '123:45') } };

        server.inject(request, (res) => {

            expect(res.result).to.exist();
            expect(res.statusCode).to.equal(403);
            done();
        });
    });
});

it('authenticates scope specified as an array', (done) => {

    const server = new Hapi.Server();
    server.connection();
    server.register(require('../'), (err) => {

        expect(err).to.not.exist();
        server.auth.strategy('default', 'basic', 'required', { validateFunc: internals.user });
        server.route({
            method: 'POST',
            path: '/',
            handler: function (request, reply) {

                return reply('ok');
            },
            config: {
                auth: {
                    scope: ['x', 'y', 'a']
                }
            }
        });

        const request = { method: 'POST', url: '/', headers: { authorization: internals.header('john', '123:45') } };

        server.inject(request, (res) => {

            expect(res.result).to.exist();
            expect(res.statusCode).to.equal(200);
            done();
        });
    });
});

it('should ask for credentials if server has one default strategy', (done) => {

    const server = new Hapi.Server();
    server.connection();
    server.register(require('../'), (err) => {

        expect(err).to.not.exist();

        server.auth.strategy('default', 'basic', { validateFunc: internals.user });
        server.route({
            path: '/',
            method: 'GET',
            config: {
                auth: 'default',
                handler: function (request, reply) {

                    return reply('ok');
                }
            }
        });

        const validOptions = { method: 'GET', url: '/', headers: { authorization: internals.header('john', '123:45') } };
        server.inject(validOptions, (res1) => {

            expect(res1.result).to.exist();
            expect(res1.statusCode).to.equal(200);

            server.inject('/', (res2) => {

                expect(res2.result).to.exist();
                expect(res2.statusCode).to.equal(401);
                done();
            });
        });
    });
});


it('cannot add a route that has payload validation required', (done) => {

    const server = new Hapi.Server();
    server.connection();
    server.register(require('../'), (err) => {

        expect(err).to.not.exist();
        server.auth.strategy('default', 'basic', 'required', { validateFunc: internals.user });

        const fn = function () {

            server.route({
                method: 'POST',
                path: '/',
                handler: function (request, reply) {

                    return reply('ok');
                },
                config: {
                    auth: {
                        mode: 'required',
                        payload: 'required'
                    }
                }
            });
        };

        expect(fn).to.throw('Payload validation can only be required when all strategies support it in /');
        done();
    });
});

it('cannot add a route that has payload validation as optional', (done) => {

    const server = new Hapi.Server();
    server.connection();
    server.register(require('../'), (err) => {

        expect(err).to.not.exist();
        server.auth.strategy('default', 'basic', 'required', { validateFunc: internals.user });

        const fn = function () {

            server.route({
                method: 'POST',
                path: '/',
                handler: function (request, reply) {

                    return reply('ok');
                },
                config: {
                    auth: {
                        mode: 'required',
                        payload: 'optional'
                    }
                }
            });
        };

        expect(fn).to.throw('Payload authentication requires at least one strategy with payload support in /');
        done();
    });
});

it('can add a route that has payload validation as none', (done) => {

    const server = new Hapi.Server();
    server.connection();
    server.register(require('../'), (err) => {

        expect(err).to.not.exist();
        server.auth.strategy('default', 'basic', 'required', { validateFunc: internals.user });

        const fn = function () {

            server.route({
                method: 'POST',
                path: '/',
                handler: function (request, reply) {

                    return reply('ok');
                },
                config: {
                    auth: {
                        mode: 'required',
                        payload: false
                    }
                }
            });
        };

        expect(fn).to.not.throw();
        done();
    });
});

it('passes non-error err in response', (done) => {

    const server = new Hapi.Server();
    server.connection();
    server.register(require('../'), (err) => {

        expect(err).to.not.exist();

        server.auth.strategy('basic', 'basic', true, {
            validateFunc: function (request, username, password, callback) {

                return callback({ some: 'value' }, false, null);
            }
        });

        server.route({
            method: 'GET',
            path: '/',
            handler: function (request, reply) {

                return reply('ok');
            }
        });

        const request = { method: 'GET', url: '/', headers: { authorization: internals.header('john', 'password') } };

        server.inject(request, (res) => {

            expect(res.result.some).to.equal('value');
            expect(res.statusCode).to.equal(200);
            done();
        });
    });
});

it('accepts request object in validateFunc', (done) => {

    const server = new Hapi.Server();
    server.connection();
    server.register(require('../'), (err) => {

        expect(err).to.not.exist();
        server.auth.strategy('default', 'basic', 'required', {

            validateFunc: function (request, username, password, callback) {

                expect(request).to.be.object();
                done();
                return;
            }
        });
        server.route({
            method: 'POST',
            path: '/',
            handler: function (request, reply) {

                return reply('ok');
            },
            config: {
                auth: 'default'
            }
        });

        const request = { method: 'POST', url: '/', headers: { authorization: internals.header('john', '123:45') } };

        server.inject(request, (res) => {

            //done();
        });
    });
});

it('includes additional attributes in WWW-Authenticate header', (done) => {

    const server = new Hapi.Server();
    server.connection();
    server.register(require('../'), (err) => {

        expect(err).to.not.exist();
        server.auth.strategy('default', 'basic', 'required', {
            validateFunc: internals.user,
            unauthorizedAttributes: { realm: 'hapi' }
        });
        server.route({
            method: 'POST',
            path: '/',
            handler: function (request, reply) {

                return reply('ok');
            },
            config: {
                auth: 'default'
            }
        });

        const request = { method: 'POST', url: '/' };

        server.inject(request, (res) => {

            const wwwAuth = 'www-authenticate';
            expect(res.headers).to.include(wwwAuth);
            expect(res.headers[wwwAuth]).to.equal('Basic realm=\"hapi\"');
            done();
        });
    });
});


internals.header = function (username, password) {

    return 'Basic ' + (new Buffer(username + ':' + password, 'utf8')).toString('base64');
};


internals.user = function (request, username, password, callback) {

    if (username === 'john') {
        return callback(null, password === '123:45', {
            user: 'john',
            scope: ['a'],
            tos: '1.0.0'
        });
    }

    if (username === 'jane') {
        return callback(Hapi.error.internal('boom'));
    }

    if (username === 'invalid1') {
        return callback(null, true, 'bad');
    }

    if (username === 'invalid2') {
        return callback(null, true, null);
    }

    return callback(null, false);
};
