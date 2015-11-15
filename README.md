### hapi-auth-basic

[![Build Status](https://secure.travis-ci.org/hapijs/hapi-auth-basic.svg)](http://travis-ci.org/hapijs/hapi-auth-basic)

Lead Maintainer: [Matt Harrison](https://github.com/mtharrison)

Basic authentication requires validating a username and password combination. The `'basic'` scheme takes the following options:

- `validateFunc` - (required) a user lookup and password validation function with the signature `function(request, username, password, callback)` where:
    - `request` - is the hapi request object of the request which is being authenticated.
    - `username` - the username received from the client.
    - `password` - the password received from the client.
    - `callback` - a callback function with the signature `function(err, isValid, credentials)` where:
        - `err` - an internal error.
        - `isValid` - `true` if both the username was found and the password matched, otherwise `false`.
        - `credentials` - a credentials object passed back to the application in `request.auth.credentials`. Typically, `credentials` are only
          included when `isValid` is `true`, but there are cases when the application needs to know who tried to authenticate even when it fails
          (e.g. with authentication mode `'try'`).
- `allowEmptyUsername` - (optional) if `true`, allows making requests with an empty username. Defaults to `false`.
- `unauthorizedAttributes` - (optional) if set, passed directly to [Boom.unauthorized](https://github.com/hapijs/boom#boomunauthorizedmessage-scheme-attributes). Useful for setting realm attribute in WWW-Authenticate header. Defaults to `undefined`.

```javascript
const Bcrypt = require('bcrypt');

const users = {
    john: {
        username: 'john',
        password: '$2a$10$iqJSHD.BGr0E2IxQwYgJmeP3NvhPrXAeLSaGCj6IR/XU5QtjVu5Tm',   // 'secret'
        name: 'John Doe',
        id: '2133d32a'
    }
};

const validate = function (request, username, password, callback) {

    const user = users[username];
    if (!user) {
        return callback(null, false);
    }

    Bcrypt.compare(password, user.password, (err, isValid) => {

        callback(err, isValid, { id: user.id, name: user.name });
    });
};

server.register(require('hapi-auth-basic'), (err) => {

    server.auth.strategy('simple', 'basic', { validateFunc: validate });
    server.route({ method: 'GET', path: '/', config: { auth: 'simple' } });
});
```
