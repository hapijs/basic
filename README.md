### hapi-auth-basic

[![Build Status](https://secure.travis-ci.org/hapijs/hapi-auth-basic.svg)](http://travis-ci.org/hapijs/hapi-auth-basic)

Lead Maintainer: [Matt Harrison](https://github.com/mtharrison)

Basic authentication requires validating a username and password combination. The `'basic'` scheme takes the following options:

- `validate` - (required) a user lookup and password validation function with the signature `[async] function(request, username, password, h)` where:
    - `request` - is the hapi request object of the request which is being authenticated.
    - `username` - the username received from the client.
    - `password` - the password received from the client.
    - `h` - the response toolkit.
    - Returns an object `{ isValid, credentials, response }` where:
        - `isValid` - `true` if both the username was found and the password matched, otherwise `false`.
        - `credentials` - a credentials object passed back to the application in `request.auth.credentials`.
        - `response` - Optional. If provided will be used immediately as a takeover response. Can be used to redirect the client, for example. Don't need to provide `isValid` or `credentials` if `response` is provided
    - Throwing an error from this function will replace default `Boom.unauthorized` error
    - Typically, `credentials` are only included when `isValid` is `true`, but there are cases when the application needs to know who tried to authenticate even when it fails (e.g. with authentication mode `'try'`).
- `allowEmptyUsername` - (optional) if `true`, allows making requests with an empty username. Defaults to `false`.
- `unauthorizedAttributes` - (optional) if set, passed directly to [Boom.unauthorized](https://github.com/hapijs/boom#boomunauthorizedmessage-scheme-attributes) if no custom `err` is thrown. Useful for setting realm attribute in WWW-Authenticate header. Defaults to `undefined`.

```javascript
const Bcrypt = require('bcrypt');
const Hapi = require('hapi');

const users = {
    john: {
        username: 'john',
        password: '$2a$10$iqJSHD.BGr0E2IxQwYgJmeP3NvhPrXAeLSaGCj6IR/XU5QtjVu5Tm',   // 'secret'
        name: 'John Doe',
        id: '2133d32a'
    }
};

const validate = async (request, username, password, h) => {

    if (username === 'help') {
        return { response: h.redirect('https://hapijs.com/help') };     // custom response
    }

    const user = users[username];
    if (!user) {
        return { credentials: null, isValid: false };
    }

    const isValid = await Bcrypt.compare(password, user.password);
    const credentials = { id: user.id, name: user.name };

    return { isValid, credentials };
};

const main = async () => {

    const server = Hapi.server({ port: 4000 });

    await server.register(require('hapi-auth-basic'));

    server.auth.strategy('simple', 'basic', { validate });
    server.auth.default('simple');

    server.route({
        method: 'GET',
        path: '/',
        handler: function (request, h) {

            return 'welcome';
        }
    });

    await server.start();

    return server;
};

main()
.then((server) => console.log(`Server listening on ${server.info.uri}`))
.catch((err) => {

    console.error(err);
    process.exit(1);
});
```
