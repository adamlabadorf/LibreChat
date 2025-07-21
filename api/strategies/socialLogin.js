const { logger } = require('@librechat/data-schemas');
const { createSocialUser, handleExistingUser } = require('./process');
const { isEnabled } = require('~/server/utils');
const { findUser } = require('~/models');

const socialLogin =
  (provider, getProfileDetails) => async (accessToken, refreshToken, idToken, profile, cb) => {
    try {
      const { email, id, avatarUrl, username, name, emailVerified } = getProfileDetails({
        idToken,
        profile,
      });

      // GitHub org membership enforcement
      if (provider === 'github') {
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
      }

      const oldUser = await findUser({ email: email.trim() });
      const ALLOW_SOCIAL_REGISTRATION = isEnabled(process.env.ALLOW_SOCIAL_REGISTRATION);

      if (oldUser) {
        await handleExistingUser(oldUser, avatarUrl);
        return cb(null, oldUser);
      }

      if (ALLOW_SOCIAL_REGISTRATION) {
        const newUser = await createSocialUser({
          email,
          avatarUrl,
          provider,
          providerKey: `${provider}Id`,
          providerId: id,
          username,
          name,
          emailVerified,
        });
        return cb(null, newUser);
      }
    } catch (err) {
      logger.error(`[${provider}Login]`, err);
      return cb(err);
    }
  };

module.exports = socialLogin;
