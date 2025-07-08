import { Env, AuditLog } from './types';
import { createLogger } from './logger';

export class AuditLogger {
  private env: Env;
  private logger: ReturnType<typeof createLogger>;

  constructor(env: Env) {
    this.env = env;
    this.logger = createLogger('Audit', env);
  }

  private generateId(): string {
    return `audit_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
  }

  private extractClientInfo(request: Request): { ip_address: string; user_agent: string } {
    return {
      ip_address: request.headers.get('CF-Connecting-IP') || 
                   request.headers.get('X-Forwarded-For')?.split(',')[0].trim() || 
                   'unknown',
      user_agent: request.headers.get('User-Agent') || 'unknown',
    };
  }

  async log(
    request: Request,
    event_type: AuditLog['event_type'],
    data: {
      client_id: string;
      user_id?: string;
      user_email?: string;
      success: boolean;
      error_code?: string;
      details?: Record<string, any>;
    }
  ): Promise<void> {
    const { ip_address, user_agent } = this.extractClientInfo(request);
    
    const auditLog: AuditLog = {
      id: this.generateId(),
      timestamp: new Date().toISOString(),
      event_type,
      client_id: data.client_id,
      user_id: data.user_id,
      user_email: data.user_email,
      ip_address,
      user_agent,
      details: data.details,
      success: data.success,
      error_code: data.error_code,
    };

    // Store in KV with TTL of 90 days
    const ttl = 90 * 24 * 60 * 60; // 90 days in seconds
    await this.env.KV.put(
      `audit:${auditLog.id}`,
      JSON.stringify(auditLog),
      { expirationTtl: ttl }
    );

    // Also store by date for easier querying
    const dateKey = `audit:date:${auditLog.timestamp.split('T')[0]}:${auditLog.id}`;
    await this.env.KV.put(dateKey, auditLog.id, { expirationTtl: ttl });

    // Log to console for immediate visibility
    this.logger.info('Audit event', {
      event_type: auditLog.event_type,
      client_id: auditLog.client_id,
      user_id: auditLog.user_id,
      success: auditLog.success,
      error_code: auditLog.error_code,
    });
  }

  async getAuditLogs(
    options: {
      startDate?: string;
      endDate?: string;
      client_id?: string;
      user_id?: string;
      event_type?: AuditLog['event_type'];
      limit?: number;
    } = {}
  ): Promise<AuditLog[]> {
    const { startDate, endDate, client_id, user_id, event_type, limit = 100 } = options;
    const logs: AuditLog[] = [];

    // If date range specified, use date index
    if (startDate || endDate) {
      const start = startDate || '2020-01-01';
      const end = endDate || new Date().toISOString().split('T')[0];
      
      const dateKeys = await this.env.KV.list({
        prefix: 'audit:date:',
        limit: 1000,
      });

      for (const key of dateKeys.keys) {
        const date = key.name.split(':')[2];
        if (date >= start && date <= end) {
          const auditId = await this.env.KV.get(key.name);
          if (auditId) {
            const auditData = await this.env.KV.get(`audit:${auditId}`);
            if (auditData) {
              const log = JSON.parse(auditData) as AuditLog;
              
              // Apply filters
              if (client_id && log.client_id !== client_id) continue;
              if (user_id && log.user_id !== user_id) continue;
              if (event_type && log.event_type !== event_type) continue;
              
              logs.push(log);
              if (logs.length >= limit) break;
            }
          }
        }
      }
    } else {
      // No date range, scan all audit logs
      const auditKeys = await this.env.KV.list({
        prefix: 'audit:',
        limit: 1000,
      });

      for (const key of auditKeys.keys) {
        if (!key.name.includes(':date:')) {
          const auditData = await this.env.KV.get(key.name);
          if (auditData) {
            const log = JSON.parse(auditData) as AuditLog;
            
            // Apply filters
            if (client_id && log.client_id !== client_id) continue;
            if (user_id && log.user_id !== user_id) continue;
            if (event_type && log.event_type !== event_type) continue;
            
            logs.push(log);
            if (logs.length >= limit) break;
          }
        }
      }
    }

    // Sort by timestamp descending
    return logs.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
  }
}