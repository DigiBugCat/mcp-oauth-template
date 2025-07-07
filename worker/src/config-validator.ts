import { Env } from './types';
import { createLogger } from './logger';

export class ConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigurationError';
  }
}

export function validateConfiguration(env: Env): void {
  const logger = createLogger('ConfigValidator', env);
  const errors: string[] = [];

  // Required fields
  const requiredFields: (keyof Env)[] = [
    'GITHUB_CLIENT_ID',
    'GITHUB_CLIENT_SECRET',
    'MCP_SERVER_URL',
    'COOKIE_ENCRYPTION_KEY',
  ];

  for (const field of requiredFields) {
    if (!env[field]) {
      errors.push(`Missing required configuration: ${field}`);
    }
  }

  // Validate GitHub OAuth configuration
  // GitHub OAuth apps can have two formats:
  // - Legacy: 20 hex characters
  // - New format: starts with "Ov23li" followed by alphanumeric characters
  if (env.GITHUB_CLIENT_ID) {
    const isLegacyFormat = /^[a-f0-9]{20}$/i.test(env.GITHUB_CLIENT_ID);
    const isNewFormat = /^Ov23li[a-zA-Z0-9]{14}$/i.test(env.GITHUB_CLIENT_ID);
    
    if (!isLegacyFormat && !isNewFormat) {
      errors.push('GITHUB_CLIENT_ID appears to be invalid format');
    }
  }

  if (env.GITHUB_CLIENT_SECRET && !env.GITHUB_CLIENT_SECRET.match(/^[a-f0-9]{40}$/i)) {
    errors.push('GITHUB_CLIENT_SECRET appears to be invalid format');
  }

  // Validate MCP server URL
  if (env.MCP_SERVER_URL) {
    try {
      new URL(env.MCP_SERVER_URL);
    } catch {
      errors.push('MCP_SERVER_URL is not a valid URL');
    }
  }

  // Validate access control lists
  if (env.ALLOWED_GITHUB_TEAMS) {
    const teams = env.ALLOWED_GITHUB_TEAMS.split(',');
    for (const team of teams) {
      if (!team.includes('/')) {
        errors.push(`Invalid team format: ${team}. Expected format: org/team`);
      }
    }
  }

  if (env.ALLOWED_EMAIL_DOMAINS) {
    const domains = env.ALLOWED_EMAIL_DOMAINS.split(',');
    for (const domain of domains) {
      if (!domain.includes('.') || domain.startsWith('.') || domain.endsWith('.')) {
        errors.push(`Invalid email domain format: ${domain}`);
      }
    }
  }

  // Validate log level
  if (env.LOG_LEVEL && !['ERROR', 'WARN', 'INFO', 'DEBUG'].includes(env.LOG_LEVEL)) {
    errors.push(`Invalid LOG_LEVEL: ${env.LOG_LEVEL}. Must be one of: ERROR, WARN, INFO, DEBUG`);
  }

  // Check for at least one access control mechanism
  if (!env.ALLOWED_GITHUB_USERS && !env.ALLOWED_GITHUB_ORGS && 
      !env.ALLOWED_GITHUB_TEAMS && !env.ALLOWED_EMAIL_DOMAINS) {
    logger.warn('No access control configured. All GitHub users will be allowed.');
  }

  if (errors.length > 0) {
    logger.error('Configuration validation failed', { errors });
    throw new ConfigurationError(`Configuration validation failed:\n${errors.join('\n')}`);
  }

  logger.info('Configuration validated successfully');
}

export function getConfigSummary(env: Env): Record<string, any> {
  return {
    environment: env.ENVIRONMENT || 'development',
    logLevel: env.LOG_LEVEL || 'INFO',
    accessControl: {
      hasUserRestrictions: !!env.ALLOWED_GITHUB_USERS,
      hasOrgRestrictions: !!env.ALLOWED_GITHUB_ORGS,
      hasTeamRestrictions: !!env.ALLOWED_GITHUB_TEAMS,
      hasEmailDomainRestrictions: !!env.ALLOWED_EMAIL_DOMAINS,
    },
    rateLimiting: {
      enabled: !!env.RATE_LIMITER,
    },
    oauth: {
      hasPreConfiguredClients: !!env.PRECONFIGURED_OAUTH_CLIENTS,
    },
  };
}