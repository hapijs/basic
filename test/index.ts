// from https://github.com/hapijs/hapi-auth-basic#hapi-auth-basic

import * as Basic from '..';
import { Server } from '@hapi/hapi';
import { types } from '@hapi/lab';

import type { Plugin } from '@hapi/hapi';

const server = new Server();

types.expect.type<Plugin<any>>(Basic);

interface User {
  username: string;
  password: string;
  name: string;
  id: string;
}

const users: {[index: string]: User} = {
  john: {
    username: 'john',
    password: '$2a$10$iqJSHD.BGr0E2IxQwYgJmeP3NvhPrXAeLSaGCj6IR/XU5QtjVu5Tm',  // 'secret'
    name: 'John Doe',
    id: '2133d32a'
  }
};

const validate: Basic.Validate = async (request, username, password, h) => {

  const user = users[username];
  if (!user) {
    return { isValid: false, credentials: null };
  }

  const isValid = true; // No need to check for type tests

  return { isValid, credentials: { id: user.id, name: user.name } };
};

server.register(Basic).then(() => {

  server.auth.strategy('simple', 'basic', { validate });
  server.auth.default('simple');

  server.route({
    method: 'GET',
    path: '/',
    handler: () => null,
    options: { auth: 'simple' }
  });
});
