const Parse = require('parse/node').Parse;
const https = require('https');

function validateAuthToken(id, token) {
  return buildRequest('users', token).then((response) => {
    if (
      response &&
      response.data &&
      response.data.length > 0 &&
      response.data[0].id === id
    ) {
      return;
    }

    throw new Parse.Error(
      Parse.Error.OBJECT_NOT_FOUND,
      'Twitch authentication is invalid for this user.'
    );
  });
}

// TODO: add config ability to parse-server settings, through options
// in function below
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
          hostname: 'api.twitch.tv',
          path: `/helix/${path}`,
          method: 'GET',
          headers: {
            Authorization: `Bearer ${token}`,
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
          `Failed to validate access token with Twitch, error message is: ${error}`
        );
      });

    request.end();
  });
}

module.exports = {
  validateAppId: validateAppId,
  validateAuthData: validateAuthData,
};
