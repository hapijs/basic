// Load modules

var Code = require('code');
var Hapi = require('hapi');
var Lab = require('lab');


// Declare internals

var internals = {};


// Test shortcuts

var lab = exports.lab = Lab.script();
var describe = lab.describe;
var it = lab.it;
var expect = Code.expect;


it('returns a reply on successful auth', function (done) {

    var server = new Hapi.Server();
    server.connection();
    server.register(require('../'), function (err) {

        expect(err).to.not.exist();
        server.auth.strategy('default', 'basic', 'required', { validateFunc: internals.user });
        server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: 'default' } });

        var request = { method: 'POST', url: '/', headers: { authorization: internals.header('john', '123:45') } };

        server.inject(request, function (res) {

            expect(res.result).to.equal('ok');
            done();
        });
    });
});

it('returns an error on wrong scheme', function (done) {

    var server = new Hapi.Server();
    server.connection();
    server.register(require('../'), function (err) {

        expect(err).to.not.exist();
        server.auth.strategy('default', 'basic', 'required', { validateFunc: internals.user });
        server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: 'default' } });

        var request = { method: 'POST', url: '/', headers: { authorization: 'Steve something' } };

        server.inject(request, function (res) {

            expect(res.statusCode).to.equal(401);
            done();
        });
    });
});

it('returns a reply on successful double auth', function (done) {

    var handler = function (request, reply) {

        var options = { method: 'POST', url: '/inner', headers: { authorization: internals.header('john', '123:45') }, credentials: request.auth.credentials };
        server.inject(options, function (res) {

            return reply(res.result);
        });
    };

    var server = new Hapi.Server();
    server.connection();
    server.register(require('../'), function (err) {

        expect(err).to.not.exist();
        server.auth.strategy('default', 'basic', 'required', { validateFunc: internals.user });
        server.route({ method: 'POST', path: '/', handler: handler });
        server.route({ method: 'POST', path: '/inner', handler: function (request, reply) { return reply('ok'); }, config: { auth: 'default' } });

        var request = { method: 'POST', url: '/', headers: { authorization: internals.header('john', '123:45') } };

        server.inject(request, function (res) {

            expect(res.result).to.equal('ok');
            done();
        });
    });
});

it('returns a reply on failed optional auth', function (done) {

    var server = new Hapi.Server();
    server.connection();
    server.register(require('../'), function (err) {

        expect(err).to.not.exist();
        server.auth.strategy('default', 'basic', 'required', { validateFunc: internals.user });
        server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: { mode: 'optional' } } });

        var request = { method: 'POST', url: '/' };

        server.inject(request, function (res) {

            expect(res.result).to.equal('ok');
            done();
        });
    });
});

it('returns an error on bad password', function (done) {

    var server = new Hapi.Server();
    server.connection();
    server.register(require('../'), function (err) {

        expect(err).to.not.exist();
        server.auth.strategy('default', 'basic', 'required', { validateFunc: internals.user });
        server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: 'default' } });

        var request = { method: 'POST', url: '/', headers: { authorization: internals.header('john', 'abcd') } };

        server.inject(request, function (res) {

            expect(res.statusCode).to.equal(401);
            done();
        });
    });
});

it('returns an error on bad header format', function (done) {

    var server = new Hapi.Server();
    server.connection();
    server.register(require('../'), function (err) {

        expect(err).to.not.exist();
        server.auth.strategy('default', 'basic', 'required', { validateFunc: internals.user });
        server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: 'default' } });

        var request = { method: 'POST', url: '/', headers: { authorization: 'basic' } };

        server.inject(request, function (res) {

            expect(res.result).to.exist();
            expect(res.statusCode).to.equal(400);
            expect(res.result.isMissing).to.equal(undefined);
            done();
        });
    });
});

it('returns an error on bad header format', function (done) {

    var server = new Hapi.Server();
    server.connection();
    server.register(require('../'), function (err) {

        expect(err).to.not.exist();
        server.auth.strategy('default', 'basic', 'required', { validateFunc: internals.user });
        server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: 'default' } });

        var request = { method: 'POST', url: '/', headers: { authorization: 'basic' } };

        server.inject(request, function (res) {

            expect(res.result).to.exist();
            expect(res.statusCode).to.equal(400);
            expect(res.result.isMissing).to.equal(undefined);
            done();
        });
    });
});

it('returns an error on bad header internal syntax', function (done) {

    var server = new Hapi.Server();
    server.connection();
    server.register(require('../'), function (err) {

        expect(err).to.not.exist();
        server.auth.strategy('default', 'basic', 'required', { validateFunc: internals.user });
        server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: 'default' } });

        var request = { method: 'POST', url: '/', headers: { authorization: 'basic 123' } };

        server.inject(request, function (res) {

            expect(res.result).to.exist();
            expect(res.statusCode).to.equal(400);
            expect(res.result.isMissing).to.equal(undefined);
            done();
        });
    });
});

it('returns an error on missing username', function (done) {

    var server = new Hapi.Server();
    server.connection();
    server.register(require('../'), function (err) {

        expect(err).to.not.exist();
        server.auth.strategy('default', 'basic', 'required', { validateFunc: internals.user });
        server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: 'default' } });

        var request = { method: 'POST', url: '/', headers: { authorization: internals.header('', '') } };

        server.inject(request, function (res) {

            expect(res.result).to.exist();
            expect(res.statusCode).to.equal(401);
            done();
        });
    });
});

it('allow missing username', function (done) {

    var server = new Hapi.Server();
    server.connection();
    server.register(require('../'), function (err) {

        expect(err).to.not.exist();

        server.auth.strategy('default', 'basic', {
            validateFunc: function (username, password, callback) { callback(null, true, {}); },
            allowEmptyUsername: true
        });

        server.route({ method: 'GET', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: 'default' } });

        server.inject({ method: 'GET', url: '/', headers: { authorization: internals.header('', 'abcd') } }, function (res) {

            expect(res.statusCode).to.equal(200);
            done();
        });
    });
});

it('returns an error on unknown user', function (done) {

    var server = new Hapi.Server();
    server.connection();
    server.register(require('../'), function (err) {

        expect(err).to.not.exist();
        server.auth.strategy('default', 'basic', 'required', { validateFunc: internals.user });
        server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: 'default' } });

        var request = { method: 'POST', url: '/', headers: { authorization: internals.header('doe', '123:45') } };

        server.inject(request, function (res) {

            expect(res.result).to.exist();
            expect(res.statusCode).to.equal(401);
            done();
        });
    });
});

it('returns an error on internal user lookup error', function (done) {

    var server = new Hapi.Server({ debug: false });
    server.connection();
    server.register(require('../'), function (err) {

        expect(err).to.not.exist();
        server.auth.strategy('default', 'basic', 'required', { validateFunc: internals.user });
        server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: 'default' } });

        var request = { method: 'POST', url: '/', headers: { authorization: internals.header('jane', '123:45') } };

        server.inject(request, function (res) {

            expect(res.result).to.exist();
            expect(res.statusCode).to.equal(500);
            done();
        });
    });
});

it('returns an error on non-object credentials error', function (done) {

    var server = new Hapi.Server({ debug: false });
    server.connection();
    server.register(require('../'), function (err) {

        expect(err).to.not.exist();
        server.auth.strategy('default', 'basic', 'required', { validateFunc: internals.user });
        server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: 'default' } });

        var request = { method: 'POST', url: '/', headers: { authorization: internals.header('invalid1', '123:45') } };

        server.inject(request, function (res) {

            expect(res.result).to.exist();
            expect(res.statusCode).to.equal(500);
            done();
        });
    });
});

it('returns an error on missing credentials error', function (done) {

    var server = new Hapi.Server({ debug: false });
    server.connection();
    server.register(require('../'), function (err) {

        expect(err).to.not.exist();
        server.auth.strategy('default', 'basic', 'required', { validateFunc: internals.user });
        server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: 'default' } });

        var request = { method: 'POST', url: '/', headers: { authorization: internals.header('invalid2', '123:45') } };

        server.inject(request, function (res) {

            expect(res.result).to.exist();
            expect(res.statusCode).to.equal(500);
            done();
        });
    });
});

it('returns an error on insufficient scope', function (done) {

    var server = new Hapi.Server();
    server.connection();
    server.register(require('../'), function (err) {

        expect(err).to.not.exist();
        server.auth.strategy('default', 'basic', 'required', { validateFunc: internals.user });
        server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: { scope: 'x' } } });

        var request = { method: 'POST', url: '/', headers: { authorization: internals.header('john', '123:45') } };

        server.inject(request, function (res) {

            expect(res.result).to.exist();
            expect(res.statusCode).to.equal(403);
            done();
        });
    });
});

it('returns an error on insufficient scope specified as an array', function (done) {

    var server = new Hapi.Server();
    server.connection();
    server.register(require('../'), function (err) {

        expect(err).to.not.exist();
        server.auth.strategy('default', 'basic', 'required', { validateFunc: internals.user });
        server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: { scope: ['x', 'y'] } } });

        var request = { method: 'POST', url: '/', headers: { authorization: internals.header('john', '123:45') } };

        server.inject(request, function (res) {

            expect(res.result).to.exist();
            expect(res.statusCode).to.equal(403);
            done();
        });
    });
});

it('authenticates scope specified as an array', function (done) {

    var server = new Hapi.Server();
    server.connection();
    server.register(require('../'), function (err) {

        expect(err).to.not.exist();
        server.auth.strategy('default', 'basic', 'required', { validateFunc: internals.user });
        server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: { scope: ['x', 'y', 'a'] } } });

        var request = { method: 'POST', url: '/', headers: { authorization: internals.header('john', '123:45') } };

        server.inject(request, function (res) {

            expect(res.result).to.exist();
            expect(res.statusCode).to.equal(200);
            done();
        });
    });
});

it('should ask for credentials if server has one default strategy', function (done) {

    var server = new Hapi.Server();
    server.connection();
    server.register(require('../'), function (err) {

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

        var validOptions = { method: 'GET', url: '/', headers: { authorization: internals.header('john', '123:45') } };
        server.inject(validOptions, function (res) {

            expect(res.result).to.exist();
            expect(res.statusCode).to.equal(200);

            server.inject('/', function (res) {

                expect(res.result).to.exist();
                expect(res.statusCode).to.equal(401);
                done();
            });
        });
    });
});


it('cannot add a route that has payload validation required', function (done) {

    var server = new Hapi.Server();
    server.connection();
    server.register(require('../'), function (err) {

        expect(err).to.not.exist();
        server.auth.strategy('default', 'basic', 'required', { validateFunc: internals.user });

        var fn = function () {

            server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: { mode: 'required', payload: 'required' } } });
        };

        expect(fn).to.throw('Payload validation can only be required when all strategies support it in path: /');
        done();
    });
});

it('cannot add a route that has payload validation as optional', function (done) {

    var server = new Hapi.Server();
    server.connection();
    server.register(require('../'), function (err) {

        expect(err).to.not.exist();
        server.auth.strategy('default', 'basic', 'required', { validateFunc: internals.user });

        var fn = function () {

            server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: { mode: 'required', payload: 'optional' } } });
        };

        expect(fn).to.throw('Payload authentication requires at least one strategy with payload support in path: /');
        done();
    });
});

it('can add a route that has payload validation as none', function (done) {

    var server = new Hapi.Server();
    server.connection();
    server.register(require('../'), function (err) {

        expect(err).to.not.exist();
        server.auth.strategy('default', 'basic', 'required', { validateFunc: internals.user });

        var fn = function () {

            server.route({ method: 'POST', path: '/', handler: function (request, reply) { return reply('ok'); }, config: { auth: { mode: 'required', payload: false } } });
        };

        expect(fn).to.not.throw();
        done();
    });
});

it('passes non-error err in response', function (done) {

    var server = new Hapi.Server();
    server.connection();
    server.register(require('../'), function (err) {

        expect(err).to.not.exist();

        server.auth.strategy('basic', 'basic', true, {
            validateFunc: function (username, password, callback) {

                return callback({ some: 'value' }, false, null);
            }
        });

        server.route({ method: 'GET', path: '/', handler: function (request, reply) { return reply('ok'); } })

        var request = { method: 'GET', url: '/', headers: { authorization: internals.header('john', 'password') } };

        server.inject(request, function (res) {

            expect(res.result.some).to.equal('value');
            expect(res.statusCode).to.equal(200);
            done();
        });
    });
});


internals.header = function (username, password) {

    return 'Basic ' + (new Buffer(username + ':' + password, 'utf8')).toString('base64');
};


internals.user = function (username, password, callback) {

    if (username === 'john') {
        return callback(null, password === '123:45', {
            user: 'john',
            scope: ['a'],
            tos: '1.0.0'
        });
    }
    else if (username === 'jane') {
        return callback(Hapi.error.internal('boom'));
    }
    else if (username === 'invalid1') {
        return callback(null, true, 'bad');
    }
    else if (username === 'invalid2') {
        return callback(null, true, null);
    }

    return callback(null, false);
};
