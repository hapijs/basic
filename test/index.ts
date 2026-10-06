import { Server } from '@hapi/hapi';
import { describe, expectTypeOf, it } from 'vitest';

import * as Basic from '../src/index.js';

import type { Plugin, Request, ResponseToolkit, ServerRegisterPluginObject } from '@hapi/hapi';

interface User {
    username: string;
    password: string;
    name: string;
    id: string;
}

const users: Record<string, User> = {
    john: {
        username: 'john',
        password: '$2a$10$iqJSHD.BGr0E2IxQwYgJmeP3NvhPrXAeLSaGCj6IR/XU5QtjVu5Tm',
        name: 'John Doe',
        id: '2133d32a',
    },
};

describe('typings', () => {
    it('exports a hapi plugin', () => {
        expectTypeOf(Basic.plugin).toEqualTypeOf<Plugin<{}>>();
        expectTypeOf(Basic).toExtend<ServerRegisterPluginObject<{}>>();
    });

    it('accepts a validate function as strategy options', async () => {
        const validate: Basic.Validate = (request, username, password, h) => {
            expectTypeOf(request).toEqualTypeOf<Request>();
            expectTypeOf(password).toEqualTypeOf<string>();
            expectTypeOf(h).toEqualTypeOf<ResponseToolkit>();

            const user = users[username];
            if (!user) {
                return Promise.resolve({ isValid: false, credentials: null });
            }

            return Promise.resolve({ isValid: true, credentials: { id: user.id, name: user.name } });
        };

        const server = new Server();
        await server.register(Basic);

        server.auth.strategy('simple', 'basic', { validate });
        server.auth.default('simple');

        server.route({
            method: 'GET',
            path: '/',
            handler: () => null,
            options: { auth: 'simple' },
        });
    });
});
