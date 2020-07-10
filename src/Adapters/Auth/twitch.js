// Returns a promise that fulfills if this id token is valid
function validateAuthData(authData, options = {}) {
  console.log(options);
  // return verifyIdToken(authData, options);
  return Promise.resolve();
}

// Returns a promise that fulfills if this app id is valid.
function validateAppId() {
  return Promise.resolve();
}

module.exports = {
  validateAppId: validateAppId,
  validateAuthData: validateAuthData,
};
