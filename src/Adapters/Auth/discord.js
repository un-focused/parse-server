const Parse = require('parse/node').Parse;
const https = require('https');

function validateAuthToken(id, token) {
  return buildRequest('users/@me', token).then((response) => {
    if (response && response.id === id) {
      return;
    }

    throw new Parse.Error(
      Parse.Error.OBJECT_NOT_FOUND,
      'Discord authentication is invalid for this user.'
    );
  });
}

// Returns a promise that fulfills if this id token is valid
function validateAuthData(authData, options = {}) {
  console.log(options);
  const { id, token } = authData;

  return validateAuthToken(id, token).then(() => {
    // validation worked
    return;
  });
}

// Returns a promise that fulfills if this app id is valid.
function validateAppId() {
  return Promise.resolve();
}

function buildRequest(path, token) {
  return new Promise((resolve, reject) => {
    const request = https
      .request(
        {
          hostname: 'discordapp.com',
          path: `/api/${path}`,
          method: 'GET',
          headers: {
            Authorization: `Bearer ${token}`,
            // "Content-Type": "application/x-www-form-urlencoded"
          },
        },
        function (response) {
          let data = '';
          response.on('data', (chunk) => {
            data += chunk;
          });

          response.on('end', () => {
            try {
              data = JSON.parse(data);
            } catch (error) {
              return reject(error);
            }

            resolve(data);
          });
        }
      )
      .on('error', (error) => {
        reject(
          `Failed to validate access token with Discord, error message is: ${error}`
        );
      });

    request.end();
  });
}

module.exports = {
  validateAppId: validateAppId,
  validateAuthData: validateAuthData,
};
