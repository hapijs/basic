import * as Boom from '@hapi/boom';
import * as Hapi from '@hapi/hapi';
import { describe, expect, it } from 'vitest';

import * as Basic from '../src/index.js';

describe('Basic authentication', () => {
    it('returns a reply on successful auth', async () => {
        const server = Hapi.server();
        await server.register(Basic);
        server.auth.strategy('default', 'basic', { validate: user });

        server.route({
            method: 'POST',
            path: '/',
            handler: function (request, h) {
                return 'ok';
            },
            options: {
                auth: 'default',
            },
        });

        const request = { method: 'POST', url: '/', headers: { authorization: header('john', '123:45') } };
        const res = await server.inject(request);

        expect(res.result).toBe('ok');
    });

    it('returns an error on wrong scheme', async () => {
        const server = Hapi.server();
        await server.register(Basic);
        server.auth.strategy('default', 'basic', { validate: user });

        server.route({
            method: 'POST',
            path: '/',
            handler: function (request, h) {
                return 'ok';
            },
            options: {
                auth: 'default',
            },
        });

        const request = { method: 'POST', url: '/', headers: { authorization: 'Steve something' } };
        const res = await server.inject(request);

        expect(res.statusCode).toBe(401);
    });

    it('returns a reply on failed optional auth', async () => {
        const server = Hapi.server();

        await server.register(Basic);

        server.auth.strategy('default', 'basic', { validate: user });
        server.route({
            method: 'POST',
            path: '/',
            handler: function (request, h) {
                return 'ok';
            },
            options: {
                auth: {
                    strategy: 'default',
                    mode: 'optional',
                },
            },
        });

        const request = { method: 'POST', url: '/' };

        const res = await server.inject(request);
        expect(res.result).toBe('ok');
    });

    it('returns an error on bad password', async () => {
        const server = Hapi.server();
        await server.register(Basic);

        server.auth.strategy('default', 'basic', { validate: user });
        server.route({
            method: 'POST',
            path: '/',
            handler: function (request, h) {
                return 'ok';
            },
            options: {
                auth: 'default',
            },
        });

        const request = { method: 'POST', url: '/', headers: { authorization: header('john', 'abcd') } };

        const res = await server.inject(request);
        expect(res.statusCode).toBe(401);
    });

    it('returns an error on bad header format', async () => {
        const server = Hapi.server();
        await server.register(Basic);

        server.auth.strategy('default', 'basic', { validate: user });
        server.route({
            method: 'POST',
            path: '/',
            handler: function (request, h) {
                return 'ok';
            },
            options: {
                auth: 'default',
            },
        });

        const request = { method: 'POST', url: '/', headers: { authorization: 'basic' } };

        const res = await server.inject(request);

        expect(res.result).toBeDefined();
        expect(res.statusCode).toBe(400);
        expect(res.result.isMissing).toBe(undefined);
    });

    it('returns an error on bad header internal syntax', async () => {
        const server = Hapi.server();
        await server.register(Basic);

        server.auth.strategy('default', 'basic', { validate: user });
        server.route({
            method: 'POST',
            path: '/',
            handler: function (request, h) {
                return 'ok';
            },
            options: {
                auth: 'default',
            },
        });

        const request = { method: 'POST', url: '/', headers: { authorization: 'basic 123' } };

        const res = await server.inject(request);

        expect(res.result).toBeDefined();
        expect(res.statusCode).toBe(400);
        expect(res.result.isMissing).toBe(undefined);
    });

    it('returns an error on missing username', async () => {
        const server = Hapi.server();
        await server.register(Basic);

        server.auth.strategy('default', 'basic', { validate: user });
        server.route({
            method: 'POST',
            path: '/',
            handler: function (request, h) {
                return 'ok';
            },
            options: {
                auth: 'default',
            },
        });

        const request = { method: 'POST', url: '/', headers: { authorization: header('', '') } };

        const res = await server.inject(request);

        expect(res.result).toBeDefined();
        expect(res.statusCode).toBe(401);
    });

    it('allows missing username', async () => {
        const server = Hapi.server();
        await server.register(Basic);

        server.auth.strategy('default', 'basic', {
            validate: () => ({ isValid: true, credentials: {} }),
            allowEmptyUsername: true,
        });

        server.route({
            method: 'GET',
            path: '/',
            handler: function (request, h) {
                return 'ok';
            },
            options: {
                auth: 'default',
            },
        });

        const res = await server.inject({ method: 'GET', url: '/', headers: { authorization: header('', 'abcd') } });

        expect(res.statusCode).toBe(200);
    });

    it('returns an error on unknown user', async () => {
        const server = Hapi.server();
        await server.register(Basic);

        server.auth.strategy('default', 'basic', { validate: user });
        server.route({
            method: 'POST',
            path: '/',
            handler: function (request, h) {
                return 'ok';
            },
            options: {
                auth: 'default',
            },
        });

        const request = { method: 'POST', url: '/', headers: { authorization: header('doe', '123:45') } };
        const res = await server.inject(request);

        expect(res.result).toBeDefined();
        expect(res.statusCode).toBe(401);
    });

    it('replies with thrown custom error', async () => {
        const server = Hapi.server({ debug: false });
        await server.register(Basic);

        server.auth.strategy('default', 'basic', { validate: user });
        server.route({
            method: 'POST',
            path: '/',
            handler: function (request, h) {
                return 'ok';
            },
            options: {
                auth: 'default',
            },
        });

        const request = { method: 'POST', url: '/', headers: { authorization: header('jane', '123:45') } };

        const res = await server.inject(request);

        expect(res.result).toBeDefined();
        expect(res.result.message).toBe('Some other problem');
        expect(res.statusCode).toBe(400);
    });

    it('replies with response response', async () => {
        const server = Hapi.server({ debug: false });
        await server.register(Basic);

        server.auth.strategy('default', 'basic', { validate: user });
        server.route({
            method: 'POST',
            path: '/',
            handler: function (request, h) {
                return 'ok';
            },
            options: {
                auth: 'default',
            },
        });

        const request = { method: 'POST', url: '/', headers: { authorization: header('bob', '123:45') } };

        const res = await server.inject(request);

        expect(res.statusCode).toBe(302);
        expect(res.headers.location).toBe('https://hapijs.com');
    });

    it('returns an error on non-object credentials error', async () => {
        const server = Hapi.server({ debug: false });
        await server.register(Basic);

        server.auth.strategy('default', 'basic', { validate: user });
        server.route({
            method: 'POST',
            path: '/',
            handler: function (request, h) {
                return 'ok';
            },
            options: {
                auth: 'default',
            },
        });

        const request = { method: 'POST', url: '/', headers: { authorization: header('invalid1', '123:45') } };

        const res = await server.inject(request);

        expect(res.result).toBeDefined();
        expect(res.statusCode).toBe(500);
    });

    it('returns an error on missing credentials error', async () => {
        const server = Hapi.server({ debug: false });
        await server.register(Basic);

        server.auth.strategy('default', 'basic', { validate: user });
        server.route({
            method: 'POST',
            path: '/',
            handler: function (request, h) {
                return 'ok';
            },
            options: {
                auth: 'default',
            },
        });

        const request = { method: 'POST', url: '/', headers: { authorization: header('invalid2', '123:45') } };

        const res = await server.inject(request);

        expect(res.result).toBeDefined();
        expect(res.statusCode).toBe(500);
    });

    it('returns an error on insufficient scope', async () => {
        const server = Hapi.server();
        await server.register(Basic);

        server.auth.strategy('default', 'basic', { validate: user });
        server.route({
            method: 'POST',
            path: '/',
            handler: function (request, h) {
                return 'ok';
            },
            options: {
                auth: {
                    strategy: 'default',
                    scope: 'x',
                },
            },
        });

        const request = { method: 'POST', url: '/', headers: { authorization: header('john', '123:45') } };

        const res = await server.inject(request);

        expect(res.result).toBeDefined();
        expect(res.statusCode).toBe(403);
    });

    it('returns an error on insufficient scope specified as an array', async () => {
        const server = Hapi.server();
        await server.register(Basic);

        server.auth.strategy('default', 'basic', { validate: user });

        server.route({
            method: 'POST',
            path: '/',
            handler: function (request, h) {
                return 'ok';
            },
            options: {
                auth: {
                    strategy: 'default',
                    scope: ['x', 'y'],
                },
            },
        });

        const request = { method: 'POST', url: '/', headers: { authorization: header('john', '123:45') } };

        const res = await server.inject(request);

        expect(res.result).toBeDefined();
        expect(res.statusCode).toBe(403);
    });

    it('authenticates scope specified as an array', async () => {
        const server = Hapi.server();
        await server.register(Basic);

        server.auth.strategy('default', 'basic', { validate: user });
        server.route({
            method: 'POST',
            path: '/',
            handler: function (request, h) {
                return 'ok';
            },
            options: {
                auth: {
                    strategy: 'default',
                    scope: ['x', 'y', 'a'],
                },
            },
        });

        const request = { method: 'POST', url: '/', headers: { authorization: header('john', '123:45') } };

        const res = await server.inject(request);

        expect(res.result).toBeDefined();
        expect(res.statusCode).toBe(200);
    });

    it('asks for credentials if server has one default strategy', async () => {
        const server = Hapi.server();
        await server.register(Basic);

        server.auth.strategy('default', 'basic', { validate: user });
        server.route({
            path: '/',
            method: 'GET',
            options: {
                auth: 'default',
                handler: function (request, h) {
                    return 'ok';
                },
            },
        });

        const validOptions = { method: 'GET', url: '/', headers: { authorization: header('john', '123:45') } };
        const res1 = await server.inject(validOptions);

        expect(res1.result).toBeDefined();
        expect(res1.statusCode).toBe(200);

        const res2 = await server.inject('/');

        expect(res2.result).toBeDefined();
        expect(res2.statusCode).toBe(401);
    });

    it('errors on a route that has payload validation required', async () => {
        const server = Hapi.server();
        await server.register(Basic);

        server.auth.strategy('default', 'basic', { validate: user });

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
                        payload: 'required',
                    },
                },
            });
        };

        expect(fn).toThrow(/^Payload validation can only be required when all strategies support it in \/$/);
    });

    it('errors on a route that has payload validation as optional', async () => {
        const server = Hapi.server();
        await server.register(Basic);

        server.auth.strategy('default', 'basic', { validate: user });

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
                        payload: 'optional',
                    },
                },
            });
        };

        expect(fn).toThrow(/^Payload authentication requires at least one strategy with payload support in \/$/);
    });

    it('adds a route that has payload validation as none', async () => {
        const server = Hapi.server();
        await server.register(Basic);

        server.auth.strategy('default', 'basic', { validate: user });

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
                        payload: false,
                    },
                },
            });
        };

        expect(fn).not.toThrow();
    });

    it('includes additional attributes in WWW-Authenticate header', async () => {
        const server = Hapi.server();
        await server.register(Basic);

        server.auth.strategy('default', 'basic', {
            validate: user,
            unauthorizedAttributes: { realm: 'hapi' },
        });

        server.route({
            method: 'POST',
            path: '/',
            handler: function (request, h) {
                return 'ok';
            },
            options: {
                auth: 'default',
            },
        });

        const request = { method: 'POST', url: '/' };

        const res = await server.inject(request);

        const wwwAuth = 'www-authenticate';
        expect(res.headers).toHaveProperty(wwwAuth);
        expect(res.headers[wwwAuth]).toBe('Basic realm="hapi"');
    });
});

function header(username, password) {
    return 'Basic ' + Buffer.from(username + ':' + password, 'utf8').toString('base64');
}

async function user(request, username, password, h) {
    if (username === 'john') {
        return await Promise.resolve({
            isValid: password === '123:45',
            credentials: {
                user: 'john',
                scope: ['a'],
                tos: '1.0.0',
            },
        });
    }

    if (username === 'jane') {
        throw Boom.badRequest('Some other problem');
    }

    if (username === 'bob') {
        return await Promise.resolve({ response: h.redirect('https://hapijs.com') });
    }

    if (username === 'invalid1') {
        return await Promise.resolve({
            isValid: true,
            credentials: 'bad',
        });
    }

    if (username === 'invalid2') {
        return await Promise.resolve({
            isValid: true,
            credentials: null,
        });
    }

    return { isValid: false };
}
