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

// GitHub-specific login function with organization checking
const githubLogin = async (accessToken, refreshToken, idToken, profile, cb) => {
  try {
    const { email, username } = getProfileDetails({ idToken, profile });

    // GitHub org membership enforcement
    const axios = require('axios');
    const allowedOrgsValue = (process.env.GITHUB_ALLOWED_ORGS || '').trim();

    if (!allowedOrgsValue) {
      logger.info(`[GitHubOrgCheck] User ${username} (${email}) denied: GITHUB_ALLOWED_ORGS is blank.`);
      return cb(null, false, { message: 'Access denied: organization login is restricted. Contact your system administrator.' });
    }

    if (allowedOrgsValue === 'all-orgs') {
      logger.info(`[GitHubOrgCheck] Allowing user ${username} (${email}) from any org (all-orgs mode).`);
    } else {
      let allowedOrgs = allowedOrgsValue.split(',').map(org => org.trim()).filter(Boolean);
      logger.info(`[GitHubOrgCheck] Checking org membership for user: ${username} (${email})`);
      logger.debug(`[GitHubOrgCheck] Allowed orgs: ${JSON.stringify(allowedOrgs)}`);

      let userOrgs = [];
      try {
        logger.info('[GitHubOrgCheck] Fetching user organizations from GitHub API...');
        const orgsRes = await axios.get('https://api.github.com/user/orgs', {
          headers: { Authorization: `Bearer ${accessToken}` },
        });
        userOrgs = orgsRes.data.map(org => org.login);
        logger.info(`[GitHubOrgCheck] User ${username} belongs to orgs: ${JSON.stringify(userOrgs)}`);
      } catch (err) {
        logger.error('[GitHubOrgCheck] Failed to fetch user orgs:', err?.response?.data || err);
        return cb(new Error('Unable to verify GitHub organization membership. Contact your system administrator.'));
      }

      const isMember = allowedOrgs.some(org => userOrgs.includes(org));
      if (!isMember) {
        logger.info(`[GitHubOrgCheck] User ${username} (${email}) denied: not a member of allowed orgs.`);
        return cb(null, false, { message: "Access denied: You must be a member of an approved GitHub organization to access this application." });
      } else {
        logger.info(`[GitHubOrgCheck] User ${username} (${email}) is a member of at least one allowed org.`);
      }
    }

    // Organization check passed, proceed with shared social login flow
    const sharedSocialLogin = socialLogin('github', getProfileDetails);
    return await sharedSocialLogin(accessToken, refreshToken, idToken, profile, cb);
  } catch (err) {
    logger.error('[githubLogin]', err);
    return cb(err);
  }
};

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
