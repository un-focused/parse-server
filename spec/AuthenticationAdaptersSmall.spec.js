const request = require('../lib/request');
const Config = require('../lib/Config');
const defaultColumns = require('../lib/Controllers/SchemaController')
  .defaultColumns;
const authenticationLoader = require('../lib/Adapters/Auth');
const path = require('path');
const responses = {
  gpgames: { playerId: 'userId' },
  instagram: { data: { id: 'userId' } },
  janrainengage: { stat: 'ok', profile: { identifier: 'userId' } },
  janraincapture: { stat: 'ok', result: 'userId' },
  line: { userId: 'userId' },
  vkontakte: { response: [{ id: 'userId' }] },
  google: { sub: 'userId' },
  wechat: { errcode: 0 },
  weibo: { uid: 'userId' },
  qq: 'callback( {"openid":"userId"} );', // yes it's like that, run eval in the client :P
  phantauth: { sub: 'userId' },
  microsoft: { id: 'userId', mail: 'userMail' },
};

describe('AuthenticationProviders', function () {
  [
    'apple',
    'discord',
    'gcenter',
    'gpgames',
    'facebook',
    'facebookaccountkit',
    'github',
    'instagram',
    'google',
    'linkedin',
    'meetup',
    'twitter',
    'janrainengage',
    'janraincapture',
    'line',
    'vkontakte',
    'qq',
    'spotify',
    'wechat',
    'weibo',
    'phantauth',
    'microsoft',
  ].map(function (providerName) {
    it('Should validate structure of ' + providerName, (done) => {
      const provider = require('../lib/Adapters/Auth/' + providerName);
      jequal(typeof provider.validateAuthData, 'function');
      jequal(typeof provider.validateAppId, 'function');
      const validateAuthDataPromise = provider.validateAuthData({}, {});
      const validateAppIdPromise = provider.validateAppId('app', 'key', {});
      jequal(
        validateAuthDataPromise.constructor,
        Promise.prototype.constructor
      );
      jequal(validateAppIdPromise.constructor, Promise.prototype.constructor);
      validateAuthDataPromise.then(
        () => {},
        () => {}
      );
      validateAppIdPromise.then(
        () => {},
        () => {}
      );
      done();
    });

    it(`should provide the right responses for adapter ${providerName}`, async () => {
      const noResponse = ['twitter', 'apple', 'discord', 'twitter', 'gcenter'];
      if (noResponse.includes(providerName)) {
        return;
      }
      spyOn(require('../lib/Adapters/Auth/httpsRequest'), 'get').and.callFake(
        (options) => {
          if (
            options ===
            'https://oauth.vk.com/access_token?client_id=appId&client_secret=appSecret&v=5.59&grant_type=client_credentials'
          ) {
            return {
              access_token: 'access_token',
            };
          }
          return Promise.resolve(responses[providerName] || { id: 'userId' });
        }
      );
      spyOn(
        require('../lib/Adapters/Auth/httpsRequest'),
        'request'
      ).and.callFake(() => {
        return Promise.resolve(responses[providerName] || { id: 'userId' });
      });
      const provider = require('../lib/Adapters/Auth/' + providerName);
      let params = {};
      if (providerName === 'vkontakte') {
        params = {
          appIds: 'appId',
          appSecret: 'appSecret',
        };
      }
      await provider.validateAuthData({ id: 'userId' }, params);
    });
  });

  const getMockMyOauthProvider = function () {
    return {
      authData: {
        id: '12345',
        access_token: '12345',
        expiration_date: new Date().toJSON(),
      },
      shouldError: false,
      loggedOut: false,
      synchronizedUserId: null,
      synchronizedAuthToken: null,
      synchronizedExpiration: null,

      authenticate: function (options) {
        if (this.shouldError) {
          options.error(this, 'An error occurred');
        } else if (this.shouldCancel) {
          options.error(this, null);
        } else {
          options.success(this, this.authData);
        }
      },
      restoreAuthentication: function (authData) {
        if (!authData) {
          this.synchronizedUserId = null;
          this.synchronizedAuthToken = null;
          this.synchronizedExpiration = null;
          return true;
        }
        this.synchronizedUserId = authData.id;
        this.synchronizedAuthToken = authData.access_token;
        this.synchronizedExpiration = authData.expiration_date;
        return true;
      },
      getAuthType: function () {
        return 'myoauth';
      },
      deauthenticate: function () {
        this.loggedOut = true;
        this.restoreAuthentication(null);
      },
    };
  };

  Parse.User.extend({
    extended: function () {
      return true;
    },
  });

  const createOAuthUser = function (callback) {
    return createOAuthUserWithSessionToken(undefined, callback);
  };

  const createOAuthUserWithSessionToken = function (token, callback) {
    const jsonBody = {
      authData: {
        myoauth: getMockMyOauthProvider().authData,
      },
    };

    const options = {
      method: 'POST',
      headers: {
        'X-Parse-Application-Id': 'test',
        'X-Parse-REST-API-Key': 'rest',
        'X-Parse-Installation-Id': 'yolo',
        'X-Parse-Session-Token': token,
        'Content-Type': 'application/json',
      },
      url: 'http://localhost:8378/1/users',
      body: jsonBody,
    };
    return request(options)
      .then((response) => {
        if (callback) {
          callback(null, response, response.data);
        }
        return {
          res: response,
          body: response.data,
        };
      })
      .catch((error) => {
        if (callback) {
          callback(error);
        }
        throw error;
      });
  };

  it('should create user with REST API', (done) => {
    createOAuthUser((error, response, body) => {
      expect(error).toBe(null);
      const b = body;
      ok(b.sessionToken);
      expect(b.objectId).not.toBeNull();
      expect(b.objectId).not.toBeUndefined();
      const sessionToken = b.sessionToken;
      const q = new Parse.Query('_Session');
      q.equalTo('sessionToken', sessionToken);
      q.first({ useMasterKey: true })
        .then((res) => {
          if (!res) {
            fail('should not fail fetching the session');
            done();
            return;
          }
          expect(res.get('installationId')).toEqual('yolo');
          done();
        })
        .catch(() => {
          fail('should not fail fetching the session');
          done();
        });
    });
  });

  it('should only create a single user with REST API', (done) => {
    let objectId;
    createOAuthUser((error, response, body) => {
      expect(error).toBe(null);
      const b = body;
      expect(b.objectId).not.toBeNull();
      expect(b.objectId).not.toBeUndefined();
      objectId = b.objectId;

      createOAuthUser((error, response, body) => {
        expect(error).toBe(null);
        const b = body;
        expect(b.objectId).not.toBeNull();
        expect(b.objectId).not.toBeUndefined();
        expect(b.objectId).toBe(objectId);
        done();
      });
    });
  });

  it("should fail to link if session token don't match user", (done) => {
    Parse.User.signUp('myUser', 'password')
      .then((user) => {
        return createOAuthUserWithSessionToken(user.getSessionToken());
      })
      .then(() => {
        return Parse.User.logOut();
      })
      .then(() => {
        return Parse.User.signUp('myUser2', 'password');
      })
      .then((user) => {
        return createOAuthUserWithSessionToken(user.getSessionToken());
      })
      .then(fail, ({ data }) => {
        expect(data.code).toBe(208);
        expect(data.error).toBe('this auth is already used');
        done();
      })
      .catch(done.fail);
  });

  it('unlink and link with custom provider', async () => {
    const provider = getMockMyOauthProvider();
    Parse.User._registerAuthenticationProvider(provider);
    const model = await Parse.User._logInWith('myoauth');
    ok(model instanceof Parse.User, 'Model should be a Parse.User');
    strictEqual(Parse.User.current(), model);
    ok(model.extended(), 'Should have used the subclass.');
    strictEqual(provider.authData.id, provider.synchronizedUserId);
    strictEqual(provider.authData.access_token, provider.synchronizedAuthToken);
    strictEqual(
      provider.authData.expiration_date,
      provider.synchronizedExpiration
    );
    ok(model._isLinked('myoauth'), 'User should be linked to myoauth');

    await model._unlinkFrom('myoauth');
    ok(!model._isLinked('myoauth'), 'User should not be linked to myoauth');
    ok(!provider.synchronizedUserId, 'User id should be cleared');
    ok(!provider.synchronizedAuthToken, 'Auth token should be cleared');
    ok(!provider.synchronizedExpiration, 'Expiration should be cleared');
    // make sure the auth data is properly deleted
    const config = Config.get(Parse.applicationId);
    const res = await config.database.adapter.find(
      '_User',
      {
        fields: Object.assign(
          {},
          defaultColumns._Default,
          defaultColumns._Installation
        ),
      },
      { objectId: model.id },
      {}
    );
    expect(res.length).toBe(1);
    expect(res[0]._auth_data_myoauth).toBeUndefined();
    expect(res[0]._auth_data_myoauth).not.toBeNull();

    await model._linkWith('myoauth');

    ok(provider.synchronizedUserId, 'User id should have a value');
    ok(provider.synchronizedAuthToken, 'Auth token should have a value');
    ok(provider.synchronizedExpiration, 'Expiration should have a value');
    ok(model._isLinked('myoauth'), 'User should be linked to myoauth');
  });

  function validateValidator(validator) {
    expect(typeof validator).toBe('function');
  }

  function validateAuthenticationHandler(authenticationHandler) {
    expect(authenticationHandler).not.toBeUndefined();
    expect(typeof authenticationHandler.getValidatorForProvider).toBe(
      'function'
    );
    expect(typeof authenticationHandler.getValidatorForProvider).toBe(
      'function'
    );
  }

  function validateAuthenticationAdapter(authAdapter) {
    expect(authAdapter).not.toBeUndefined();
    if (!authAdapter) {
      return;
    }
    expect(typeof authAdapter.validateAuthData).toBe('function');
    expect(typeof authAdapter.validateAppId).toBe('function');
  }

  it('properly loads custom adapter', (done) => {
    const validAuthData = {
      id: 'hello',
      token: 'world',
    };
    const adapter = {
      validateAppId: function () {
        return Promise.resolve();
      },
      validateAuthData: function (authData) {
        if (
          authData.id == validAuthData.id &&
          authData.token == validAuthData.token
        ) {
          return Promise.resolve();
        }
        return Promise.reject();
      },
    };

    const authDataSpy = spyOn(adapter, 'validateAuthData').and.callThrough();
    const appIdSpy = spyOn(adapter, 'validateAppId').and.callThrough();

    const authenticationHandler = authenticationLoader({
      customAuthentication: adapter,
    });

    validateAuthenticationHandler(authenticationHandler);
    const validator = authenticationHandler.getValidatorForProvider(
      'customAuthentication'
    );
    validateValidator(validator);

    validator(validAuthData).then(
      () => {
        expect(authDataSpy).toHaveBeenCalled();
        // AppIds are not provided in the adapter, should not be called
        expect(appIdSpy).not.toHaveBeenCalled();
        done();
      },
      (err) => {
        jfail(err);
        done();
      }
    );
  });

  it('properly loads custom adapter module object', (done) => {
    const authenticationHandler = authenticationLoader({
      customAuthentication: path.resolve('./spec/support/CustomAuth.js'),
    });

    validateAuthenticationHandler(authenticationHandler);
    const validator = authenticationHandler.getValidatorForProvider(
      'customAuthentication'
    );
    validateValidator(validator);

    validator({
      token: 'my-token',
    }).then(
      () => {
        done();
      },
      (err) => {
        jfail(err);
        done();
      }
    );
  });

  it('properly loads custom adapter module object (again)', (done) => {
    const authenticationHandler = authenticationLoader({
      customAuthentication: {
        module: path.resolve('./spec/support/CustomAuthFunction.js'),
        options: { token: 'valid-token' },
      },
    });

    validateAuthenticationHandler(authenticationHandler);
    const validator = authenticationHandler.getValidatorForProvider(
      'customAuthentication'
    );
    validateValidator(validator);

    validator({
      token: 'valid-token',
    }).then(
      () => {
        done();
      },
      (err) => {
        jfail(err);
        done();
      }
    );
  });

  it('properly loads a default adapter with options', () => {
    const options = {
      facebook: {
        appIds: ['a', 'b'],
        appSecret: 'secret',
      },
    };
    const {
      adapter,
      appIds,
      providerOptions,
    } = authenticationLoader.loadAuthAdapter('facebook', options);
    validateAuthenticationAdapter(adapter);
    expect(appIds).toEqual(['a', 'b']);
    expect(providerOptions).toEqual(options.facebook);
  });

  it('properly loads a custom adapter with options', () => {
    const options = {
      custom: {
        validateAppId: () => {},
        validateAuthData: () => {},
        appIds: ['a', 'b'],
      },
    };
    const {
      adapter,
      appIds,
      providerOptions,
    } = authenticationLoader.loadAuthAdapter('custom', options);
    validateAuthenticationAdapter(adapter);
    expect(appIds).toEqual(['a', 'b']);
    expect(providerOptions).toEqual(options.custom);
  });
});

describe('discord auth adapter', () => {
  const discord = require('../lib/Adapters/Auth/discord');

  it('should work', async (done) => {
    await discord.validateAuthData(
      {
        id: '',
        token: 'GJdchHVde2Qb2sUd8gHkFyDftZMTTJ',
      },
      {}
    );
    done();
  });
});

describe('twitch auth adapter', () => {
  const twitch = require('../lib/Adapters/Auth/twitch');

  it('should work', async (done) => {
    await twitch.validateAuthData(
      {
        id: '',
        token: '',
      },
      {
        clientId: '',
      }
    );
    done();
  });
});

//   it('(using client id as array) should throw error with missing id_token', async () => {
//     try {
//       await apple.validateAuthData({}, { client_id: ['secret'] });
//       fail();
//     } catch (e) {
//       expect(e.message).toBe('id token is invalid for this user.');
//     }
//   });

//   it('should not decode invalid id_token', async () => {
//     try {
//       await apple.validateAuthData(
//         { id: 'the_user_id', token: 'the_token' },
//         { clientId: 'secret' }
//       );
//       fail();
//     } catch (e) {
//       expect(e.message).toBe('provided token does not decode as JWT');
//     }
//   });

//   it('should throw error if public key used to encode token is not available', async () => {
//     const fakeDecodedToken = { header: { kid: '789', alg: 'RS256' } };
//     try {
//       spyOn(jwt, 'decode').and.callFake(() => fakeDecodedToken);

//       await apple.validateAuthData(
//         { id: 'the_user_id', token: 'the_token' },
//         { clientId: 'secret' }
//       );
//       fail();
//     } catch (e) {
//       expect(e.message).toBe(
//         `Unable to find matching key for Key ID: ${fakeDecodedToken.header.kid}`
//       );
//     }
//   });

//   it('should use algorithm from key header to verify id_token', async () => {
//     const fakeClaim = {
//       iss: 'https://appleid.apple.com',
//       aud: 'secret',
//       exp: Date.now(),
//       sub: 'the_user_id',
//     };
//     const fakeDecodedToken = { header: { kid: '123', alg: 'RS256' } };
//     spyOn(jwt, 'decode').and.callFake(() => fakeDecodedToken);
//     spyOn(jwt, 'verify').and.callFake(() => fakeClaim);
//     const fakeGetSigningKeyAsyncFunction = () => {
//       return { kid: '123', rsaPublicKey: 'the_rsa_public_key' };
//     };
//     spyOn(util, 'promisify').and.callFake(() => fakeGetSigningKeyAsyncFunction);

//     const result = await apple.validateAuthData(
//       { id: 'the_user_id', token: 'the_token' },
//       { clientId: 'secret' }
//     );
//     expect(result).toEqual(fakeClaim);
//     expect(jwt.verify.calls.first().args[2].algorithms).toEqual(
//       fakeDecodedToken.header.alg
//     );
//   });

//   it('should not verify invalid id_token', async () => {
//     const fakeDecodedToken = { header: { kid: '123', alg: 'RS256' } };
//     spyOn(jwt, 'decode').and.callFake(() => fakeDecodedToken);
//     const fakeGetSigningKeyAsyncFunction = () => {
//       return { kid: '123', rsaPublicKey: 'the_rsa_public_key' };
//     };
//     spyOn(util, 'promisify').and.callFake(() => fakeGetSigningKeyAsyncFunction);

//     try {
//       await apple.validateAuthData(
//         { id: 'the_user_id', token: 'the_token' },
//         { clientId: 'secret' }
//       );
//       fail();
//     } catch (e) {
//       expect(e.message).toBe('jwt malformed');
//     }
//   });

//   it('(using client id as array) should not verify invalid id_token', async () => {
//     try {
//       await apple.validateAuthData(
//         { id: 'the_user_id', token: 'the_token' },
//         { client_id: ['secret'] }
//       );
//       fail();
//     } catch (e) {
//       expect(e.message).toBe('provided token does not decode as JWT');
//     }
//   });

//   it('(using client id as string) should verify id_token', async () => {
//     const fakeClaim = {
//       iss: 'https://appleid.apple.com',
//       aud: 'secret',
//       exp: Date.now(),
//       sub: 'the_user_id',
//     };
//     const fakeDecodedToken = { header: { kid: '123', alg: 'RS256' } };
//     spyOn(jwt, 'decode').and.callFake(() => fakeDecodedToken);
//     const fakeGetSigningKeyAsyncFunction = () => {
//       return { kid: '123', rsaPublicKey: 'the_rsa_public_key' };
//     };
//     spyOn(util, 'promisify').and.callFake(() => fakeGetSigningKeyAsyncFunction);
//     spyOn(jwt, 'verify').and.callFake(() => fakeClaim);

//     const result = await apple.validateAuthData(
//       { id: 'the_user_id', token: 'the_token' },
//       { clientId: 'secret' }
//     );
//     expect(result).toEqual(fakeClaim);
//   });

//   it('(using client id as array) should verify id_token', async () => {
//     const fakeClaim = {
//       iss: 'https://appleid.apple.com',
//       aud: 'secret',
//       exp: Date.now(),
//       sub: 'the_user_id',
//     };
//     const fakeDecodedToken = { header: { kid: '123', alg: 'RS256' } };
//     spyOn(jwt, 'decode').and.callFake(() => fakeDecodedToken);
//     const fakeGetSigningKeyAsyncFunction = () => {
//       return { kid: '123', rsaPublicKey: 'the_rsa_public_key' };
//     };
//     spyOn(util, 'promisify').and.callFake(() => fakeGetSigningKeyAsyncFunction);
//     spyOn(jwt, 'verify').and.callFake(() => fakeClaim);

//     const result = await apple.validateAuthData(
//       { id: 'the_user_id', token: 'the_token' },
//       { clientId: ['secret'] }
//     );
//     expect(result).toEqual(fakeClaim);
//   });

//   it('(using client id as array with multiple items) should verify id_token', async () => {
//     const fakeClaim = {
//       iss: 'https://appleid.apple.com',
//       aud: 'secret',
//       exp: Date.now(),
//       sub: 'the_user_id',
//     };
//     const fakeDecodedToken = { header: { kid: '123', alg: 'RS256' } };
//     spyOn(jwt, 'decode').and.callFake(() => fakeDecodedToken);
//     const fakeGetSigningKeyAsyncFunction = () => {
//       return { kid: '123', rsaPublicKey: 'the_rsa_public_key' };
//     };
//     spyOn(util, 'promisify').and.callFake(() => fakeGetSigningKeyAsyncFunction);
//     spyOn(jwt, 'verify').and.callFake(() => fakeClaim);

//     const result = await apple.validateAuthData(
//       { id: 'the_user_id', token: 'the_token' },
//       { clientId: ['secret', 'secret 123'] }
//     );
//     expect(result).toEqual(fakeClaim);
//   });

//   it('(using client id as string) should throw error with with invalid jwt issuer', async () => {
//     const fakeClaim = {
//       iss: 'https://not.apple.com',
//       sub: 'the_user_id',
//     };
//     const fakeDecodedToken = { header: { kid: '123', alg: 'RS256' } };
//     spyOn(jwt, 'decode').and.callFake(() => fakeDecodedToken);
//     const fakeGetSigningKeyAsyncFunction = () => {
//       return { kid: '123', rsaPublicKey: 'the_rsa_public_key' };
//     };
//     spyOn(util, 'promisify').and.callFake(() => fakeGetSigningKeyAsyncFunction);
//     spyOn(jwt, 'verify').and.callFake(() => fakeClaim);

//     try {
//       await apple.validateAuthData(
//         { id: 'the_user_id', token: 'the_token' },
//         { clientId: 'secret' }
//       );
//       fail();
//     } catch (e) {
//       expect(e.message).toBe(
//         'id token not issued by correct OpenID provider - expected: https://appleid.apple.com | from: https://not.apple.com'
//       );
//     }
//   });

//   // TODO: figure out a way to generate our own apple signed tokens, perhaps with a parse apple account
//   // and a private key
//   xit('(using client id as array) should throw error with with invalid jwt issuer', async () => {
//     const fakeClaim = {
//       iss: 'https://not.apple.com',
//       sub: 'the_user_id',
//     };
//     const fakeDecodedToken = { header: { kid: '123', alg: 'RS256' } };
//     spyOn(jwt, 'decode').and.callFake(() => fakeDecodedToken);
//     const fakeGetSigningKeyAsyncFunction = () => {
//       return { kid: '123', rsaPublicKey: 'the_rsa_public_key' };
//     };
//     spyOn(util, 'promisify').and.callFake(() => fakeGetSigningKeyAsyncFunction);
//     spyOn(jwt, 'verify').and.callFake(() => fakeClaim);

//     try {
//       await apple.validateAuthData(
//         {
//           id: 'INSERT ID HERE',
//           token: 'INSERT APPLE TOKEN HERE WITH INVALID JWT ISSUER',
//         },
//         { clientId: ['INSERT CLIENT ID HERE'] }
//       );
//       fail();
//     } catch (e) {
//       expect(e.message).toBe(
//         'id token not issued by correct OpenID provider - expected: https://appleid.apple.com | from: https://not.apple.com'
//       );
//     }
//   });

//   it('(using client id as string) should throw error with with invalid jwt issuer', async () => {
//     const fakeClaim = {
//       iss: 'https://not.apple.com',
//       sub: 'the_user_id',
//     };
//     const fakeDecodedToken = { header: { kid: '123', alg: 'RS256' } };
//     spyOn(jwt, 'decode').and.callFake(() => fakeDecodedToken);
//     const fakeGetSigningKeyAsyncFunction = () => {
//       return { kid: '123', rsaPublicKey: 'the_rsa_public_key' };
//     };
//     spyOn(util, 'promisify').and.callFake(() => fakeGetSigningKeyAsyncFunction);
//     spyOn(jwt, 'verify').and.callFake(() => fakeClaim);

//     try {
//       await apple.validateAuthData(
//         {
//           id: 'INSERT ID HERE',
//           token: 'INSERT APPLE TOKEN HERE WITH INVALID JWT ISSUER',
//         },
//         { clientId: 'INSERT CLIENT ID HERE' }
//       );
//       fail();
//     } catch (e) {
//       expect(e.message).toBe(
//         'id token not issued by correct OpenID provider - expected: https://appleid.apple.com | from: https://not.apple.com'
//       );
//     }
//   });

//   // TODO: figure out a way to generate our own apple signed tokens, perhaps with a parse apple account
//   // and a private key
//   xit('(using client id as string) should throw error with invalid jwt client_id', async () => {
//     try {
//       await apple.validateAuthData(
//         { id: 'INSERT ID HERE', token: 'INSERT APPLE TOKEN HERE' },
//         { clientId: 'secret' }
//       );
//       fail();
//     } catch (e) {
//       expect(e.message).toBe('jwt audience invalid. expected: secret');
//     }
//   });

//   // TODO: figure out a way to generate our own apple signed tokens, perhaps with a parse apple account
//   // and a private key
//   xit('(using client id as array) should throw error with invalid jwt client_id', async () => {
//     try {
//       await apple.validateAuthData(
//         { id: 'INSERT ID HERE', token: 'INSERT APPLE TOKEN HERE' },
//         { clientId: ['secret'] }
//       );
//       fail();
//     } catch (e) {
//       expect(e.message).toBe('jwt audience invalid. expected: secret');
//     }
//   });

//   // TODO: figure out a way to generate our own apple signed tokens, perhaps with a parse apple account
//   // and a private key
//   xit('should throw error with invalid user id', async () => {
//     try {
//       await apple.validateAuthData(
//         { id: 'invalid user', token: 'INSERT APPLE TOKEN HERE' },
//         { clientId: 'INSERT CLIENT ID HERE' }
//       );
//       fail();
//     } catch (e) {
//       expect(e.message).toBe('auth data is invalid for this user.');
//     }
//   });

//   it('should throw error with with invalid user id', async () => {
//     const fakeClaim = {
//       iss: 'https://appleid.apple.com',
//       aud: 'invalid_client_id',
//       sub: 'a_different_user_id',
//     };
//     const fakeDecodedToken = { header: { kid: '123', alg: 'RS256' } };
//     spyOn(jwt, 'decode').and.callFake(() => fakeDecodedToken);
//     const fakeGetSigningKeyAsyncFunction = () => {
//       return { kid: '123', rsaPublicKey: 'the_rsa_public_key' };
//     };
//     spyOn(util, 'promisify').and.callFake(() => fakeGetSigningKeyAsyncFunction);
//     spyOn(jwt, 'verify').and.callFake(() => fakeClaim);

//     try {
//       await apple.validateAuthData(
//         { id: 'the_user_id', token: 'the_token' },
//         { clientId: 'secret' }
//       );
//       fail();
//     } catch (e) {
//       expect(e.message).toBe('auth data is invalid for this user.');
//     }
//   });
// });
