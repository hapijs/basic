// Load modules

var Lab = require('lab');
var Hapi = require('hapi');


// Test shortcuts

var expect = Lab.expect;
var before = Lab.before;
var it = Lab.test;


var basicHeader = function (username, password) {

    return 'Basic ' + (new Buffer(username + ':' + password, 'utf8')).toString('base64');
};

var loadUser = function (username, password, callback) {

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

var basicHandler = function (request, reply) {

    reply('ok');
};

var doubleHandler = function (request, reply) {

    var options = { method: 'POST', url: '/basic', headers: { authorization: basicHeader('john', '123:45') }, credentials: request.auth.credentials };

    server.inject(options, function (res) {

        reply(res.result);
    });
};

var server = new Hapi.Server({ debug: false });
before(function (done) {

    server.pack.register(require('../'), function (err) {

        expect(err).to.not.exist;
        server.auth.strategy('default', 'basic', 'required', { validateFunc: loadUser });

        server.route([
            { method: 'POST', path: '/basic', handler: basicHandler, config: { auth: 'default' } },
            { method: 'POST', path: '/basicOptional', handler: basicHandler, config: { auth: { mode: 'optional' } } },
            { method: 'POST', path: '/basicScope', handler: basicHandler, config: { auth: { scope: 'x' } } },
            { method: 'POST', path: '/basicArrayScope', handler: basicHandler, config: { auth: { scope: ['x', 'y'] } } },
            { method: 'POST', path: '/basicArrayScopeA', handler: basicHandler, config: { auth: { scope: ['x', 'y', 'a'] } } },
            { method: 'POST', path: '/basicTos', handler: basicHandler, config: { auth: { tos: '1.1.x' } } },
            { method: 'POST', path: '/double', handler: doubleHandler }
        ]);

        done();
    });
});

it('returns a reply on successful auth', function (done) {

    var request = { method: 'POST', url: '/basic', headers: { authorization: basicHeader('john', '123:45') } };

    server.inject(request, function (res) {

        expect(res.result).to.exist;
        expect(res.result).to.equal('ok');
        done();
    });
});

it('returns an error on wrong scheme', function (done) {

    var request = { method: 'POST', url: '/basic', headers: { authorization: 'Steve something' } };

    server.inject(request, function (res) {

        expect(res.statusCode).to.equal(401);
        done();
    });
});

it('returns a reply on successful double auth', function (done) {

    var request = { method: 'POST', url: '/double', headers: { authorization: basicHeader('john', '123:45') } };

    server.inject(request, function (res) {

        expect(res.result).to.exist;
        expect(res.result).to.equal('ok');
        done();
    });
});

it('returns a reply on failed optional auth', function (done) {

    var request = { method: 'POST', url: '/basicOptional' };

    server.inject(request, function (res) {

        expect(res.result).to.equal('ok');
        done();
    });
});

it('returns an error on bad password', function (done) {

    var request = { method: 'POST', url: '/basic', headers: { authorization: basicHeader('john', 'abcd') } };

    server.inject(request, function (res) {

        expect(res.statusCode).to.equal(401);
        done();
    });
});

it('returns an error on bad header format', function (done) {

    var request = { method: 'POST', url: '/basic', headers: { authorization: 'basic' } };

    server.inject(request, function (res) {

        expect(res.result).to.exist;
        expect(res.statusCode).to.equal(400);
        expect(res.result.isMissing).to.equal(undefined);
        done();
    });
});

it('returns an error on bad header format', function (done) {

    var request = { method: 'POST', url: '/basic', headers: { authorization: 'basic' } };

    server.inject(request, function (res) {

        expect(res.result).to.exist;
        expect(res.statusCode).to.equal(400);
        expect(res.result.isMissing).to.equal(undefined);
        done();
    });
});

it('returns an error on bad header internal syntax', function (done) {

    var request = { method: 'POST', url: '/basic', headers: { authorization: 'basic 123' } };

    server.inject(request, function (res) {

        expect(res.result).to.exist;
        expect(res.statusCode).to.equal(400);
        expect(res.result.isMissing).to.equal(undefined);
        done();
    });
});

it('returns an error on missing username', function (done) {

    var request = { method: 'POST', url: '/basic', headers: { authorization: basicHeader('', '') } };

    server.inject(request, function (res) {

        expect(res.result).to.exist;
        expect(res.statusCode).to.equal(401);
        done();
    });
});

it('allow missing username', function (done) {

    var server = new Hapi.Server();
    server.pack.register(require('../'), function (err) {

        expect(err).to.not.exist;

        server.auth.strategy('default', 'basic', {
            validateFunc: function (username, password, callback) { callback(null, true, {}); },
            allowEmptyUsername: true
        });

        server.route({ method: 'GET', path: '/', handler: function (request, reply) { reply('ok'); }, config: { auth: 'default' } });

        server.inject({ method: 'GET', url: '/', headers: { authorization: basicHeader('', 'abcd') } }, function (res) {

            expect(res.statusCode).to.equal(200);
            done();
        });
    });
});

it('returns an error on unknown user', function (done) {

    var request = { method: 'POST', url: '/basic', headers: { authorization: basicHeader('doe', '123:45') } };

    server.inject(request, function (res) {

        expect(res.result).to.exist;
        expect(res.statusCode).to.equal(401);
        done();
    });
});

it('returns an error on internal user lookup error', function (done) {

    var request = { method: 'POST', url: '/basic', headers: { authorization: basicHeader('jane', '123:45') } };

    server.inject(request, function (res) {

        expect(res.result).to.exist;
        expect(res.statusCode).to.equal(500);
        done();
    });
});

it('returns an error on non-object credentials error', function (done) {

    var request = { method: 'POST', url: '/basic', headers: { authorization: basicHeader('invalid1', '123:45') } };

    server.inject(request, function (res) {

        expect(res.result).to.exist;
        expect(res.statusCode).to.equal(500);
        done();
    });
});

it('returns an error on missing credentials error', function (done) {

    var request = { method: 'POST', url: '/basic', headers: { authorization: basicHeader('invalid2', '123:45') } };

    server.inject(request, function (res) {

        expect(res.result).to.exist;
        expect(res.statusCode).to.equal(500);
        done();
    });
});

it('returns an error on insufficient tos', function (done) {

    var request = { method: 'POST', url: '/basicTos', headers: { authorization: basicHeader('john', '123:45') } };

    server.inject(request, function (res) {

        expect(res.result).to.exist;
        expect(res.statusCode).to.equal(403);
        done();
    });
});

it('returns an error on insufficient scope', function (done) {

    var request = { method: 'POST', url: '/basicScope', headers: { authorization: basicHeader('john', '123:45') } };

    server.inject(request, function (res) {

        expect(res.result).to.exist;
        expect(res.statusCode).to.equal(403);
        done();
    });
});

it('returns an error on insufficient scope specified as an array', function (done) {

    var request = { method: 'POST', url: '/basicArrayScope', headers: { authorization: basicHeader('john', '123:45') } };

    server.inject(request, function (res) {

        expect(res.result).to.exist;
        expect(res.statusCode).to.equal(403);
        done();
    });
});

it('authenticates scope specified as an array', function (done) {

    var request = { method: 'POST', url: '/basicArrayScopeA', headers: { authorization: basicHeader('john', '123:45') } };

    server.inject(request, function (res) {

        expect(res.result).to.exist;
        expect(res.statusCode).to.equal(200);
        done();
    });
});

it('should ask for credentials if server has one default strategy', function (done) {

    var server = new Hapi.Server();
    server.pack.register(require('../'), function (err) {

        expect(err).to.not.exist;

        server.auth.strategy('default', 'basic', { validateFunc: loadUser });
        server.route({
            path: '/noauth',
            method: 'GET',
            config: {
                auth: 'default',
                handler: function (request, reply) {

                    reply('ok');
                }
            }
        });

        var validOptions = { method: 'GET', url: '/noauth', headers: { authorization: basicHeader('john', '123:45') } };
        server.inject(validOptions, function (res) {

            expect(res.result).to.exist;
            expect(res.statusCode).to.equal(200);

            server.inject('/noauth', function (res) {

                expect(res.result).to.exist;
                expect(res.statusCode).to.equal(401);
                done();
            });
        });
    });
});


it('cannot add a route that has payload validation required', function (done) {

    var fn = function () {

        server.route({ method: 'POST', path: '/basicPayload', handler: basicHandler, config: { auth: { mode: 'required', payload: 'required' } } });
    };

    expect(fn).to.throw(Error);
    done();
});

it('cannot add a route that has payload validation as optional', function (done) {

    var fn = function () {

        server.route({ method: 'POST', path: '/basicPayload', handler: basicHandler, config: { auth: { mode: 'required', payload: 'optional' } } });
    };

    expect(fn).to.throw(Error);
    done();
});

it('can add a route that has payload validation as none', function (done) {

    var fn = function () {

        server.route({ method: 'POST', path: '/basicPayload', handler: basicHandler, config: { auth: { mode: 'required', payload: false } } });
    };

    expect(fn).to.not.throw(Error);
    done();
});

it('passes non-error err in response', function (done) {

    var server = new Hapi.Server();
    server.pack.register(require('../'), function (err) {

        expect(err).to.not.exist;

        server.auth.strategy('basic', 'basic', true, {
            validateFunc: function (username, password, callback) {

                return callback({ some: 'value' }, false, null);
            }
        });

        server.route({ method: 'GET', path: '/', handler: basicHandler })

        var request = { method: 'GET', url: '/', headers: { authorization: basicHeader('john', 'password') } };

        server.inject(request, function (res) {

            expect(res.result.some).to.equal('value');
            expect(res.statusCode).to.equal(200);
            done();
        });
    });
});
