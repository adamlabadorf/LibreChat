const { Strategy: GitHubStrategy } = require('passport-github2');
const socialLogin = require('./socialLogin');
const { logger } = require('@librechat/data-schemas');

const getProfileDetails = ({ profile }) => ({
  email: profile.emails[0].value,
  id: profile.id,
  avatarUrl: profile.photos[0].value,
  username: profile.username,
  name: profile.displayName,
  emailVerified: profile.emails[0].verified,
});

const githubLogin = socialLogin('github', getProfileDetails);

const githubScope = ['user:email', 'read:org'];
logger.info(`[GitHubStrategy] Using OAuth scope: ${JSON.stringify(githubScope)}`);

module.exports = () =>
  new GitHubStrategy(
    {
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: `${process.env.DOMAIN_SERVER}${process.env.GITHUB_CALLBACK_URL}`,
      proxy: false,
      scope: githubScope,
      ...(process.env.GITHUB_ENTERPRISE_BASE_URL && {
        authorizationURL: `${process.env.GITHUB_ENTERPRISE_BASE_URL}/login/oauth/authorize`,
        tokenURL: `${process.env.GITHUB_ENTERPRISE_BASE_URL}/login/oauth/access_token`,
        userProfileURL: `${process.env.GITHUB_ENTERPRISE_BASE_URL}/api/v3/user`,
        userEmailURL: `${process.env.GITHUB_ENTERPRISE_BASE_URL}/api/v3/user/emails`,
        ...(process.env.GITHUB_ENTERPRISE_USER_AGENT && {
          userAgent: process.env.GITHUB_ENTERPRISE_USER_AGENT,
        }),
      }),
    },
    githubLogin,
  );
