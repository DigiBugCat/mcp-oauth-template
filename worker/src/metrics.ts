import { Env } from './types';
import { createLogger } from './logger';

export interface Metric {
  name: string;
  value: number;
  timestamp: number;
  labels?: Record<string, string>;
}

export class MetricsCollector {
  private env: Env;
  private logger: ReturnType<typeof createLogger>;
  private buffer: Metric[] = [];
  private flushInterval = 60000; // 1 minute
  private lastFlush = Date.now();

  constructor(env: Env) {
    this.env = env;
    this.logger = createLogger('Metrics', env);
  }

  recordCounter(name: string, value: number = 1, labels?: Record<string, string>): void {
    this.buffer.push({
      name,
      value,
      timestamp: Date.now(),
      labels,
    });
    
    this.checkFlush();
  }

  recordGauge(name: string, value: number, labels?: Record<string, string>): void {
    this.buffer.push({
      name,
      value,
      timestamp: Date.now(),
      labels,
    });
    
    this.checkFlush();
  }

  recordHistogram(name: string, value: number, labels?: Record<string, string>): void {
    this.buffer.push({
      name,
      value,
      timestamp: Date.now(),
      labels,
    });
    
    this.checkFlush();
  }

  async recordRequestMetrics(
    request: Request,
    response: Response,
    startTime: number
  ): Promise<void> {
    const duration = Date.now() - startTime;
    const url = new URL(request.url);
    
    // Record request count
    this.recordCounter('oauth_requests_total', 1, {
      method: request.method,
      path: url.pathname,
      status: response.status.toString(),
    });
    
    // Record request duration
    this.recordHistogram('oauth_request_duration_ms', duration, {
      method: request.method,
      path: url.pathname,
      status: response.status.toString(),
    });
    
    // Record error rate
    if (response.status >= 400) {
      this.recordCounter('oauth_errors_total', 1, {
        method: request.method,
        path: url.pathname,
        status: response.status.toString(),
      });
    }
  }

  private checkFlush(): void {
    if (this.buffer.length > 100 || Date.now() - this.lastFlush > this.flushInterval) {
      this.flush().catch(error => {
        this.logger.error('Failed to flush metrics', { error: error.message });
      });
    }
  }

  async flush(): Promise<void> {
    if (this.buffer.length === 0) return;
    
    const metrics = [...this.buffer];
    this.buffer = [];
    this.lastFlush = Date.now();
    
    // Store metrics in KV with hourly buckets
    const hour = new Date().toISOString().substring(0, 13);
    const key = `metrics:${hour}:${Date.now()}`;
    
    try {
      await this.env.OAUTH_KV.put(
        key,
        JSON.stringify(metrics),
        { expirationTtl: 7 * 24 * 60 * 60 } // 7 days
      );
      
      this.logger.debug('Metrics flushed', { count: metrics.length });
    } catch (error) {
      this.logger.error('Failed to store metrics', { error: error.message });
      // Put metrics back in buffer to retry
      this.buffer.unshift(...metrics);
    }
  }

  async getMetrics(
    startTime: number,
    endTime: number,
    metricName?: string
  ): Promise<Metric[]> {
    const metrics: Metric[] = [];
    
    // Calculate hourly buckets to query
    const startHour = new Date(startTime).toISOString().substring(0, 13);
    const endHour = new Date(endTime).toISOString().substring(0, 13);
    
    // List all metric keys in the time range
    const keys = await this.env.OAUTH_KV.list({
      prefix: 'metrics:',
      limit: 1000,
    });
    
    for (const key of keys.keys) {
      const hour = key.name.split(':')[1];
      if (hour >= startHour && hour <= endHour) {
        const data = await this.env.OAUTH_KV.get(key.name);
        if (data) {
          try {
            const bucketMetrics = JSON.parse(data) as Metric[];
            for (const metric of bucketMetrics) {
              if (metric.timestamp >= startTime && metric.timestamp <= endTime) {
                if (!metricName || metric.name === metricName) {
                  metrics.push(metric);
                }
              }
            }
          } catch (error) {
            this.logger.error('Failed to parse metrics', { 
              key: key.name,
              error: error.message,
            });
          }
        }
      }
    }
    
    return metrics.sort((a, b) => a.timestamp - b.timestamp);
  }

  async getAggregatedMetrics(
    startTime: number,
    endTime: number,
    metricName: string,
    aggregation: 'sum' | 'avg' | 'max' | 'min' | 'count' = 'sum'
  ): Promise<Record<string, number>> {
    const metrics = await this.getMetrics(startTime, endTime, metricName);
    const groups: Record<string, number[]> = {};
    
    // Group by labels
    for (const metric of metrics) {
      const labelKey = JSON.stringify(metric.labels || {});
      if (!groups[labelKey]) {
        groups[labelKey] = [];
      }
      groups[labelKey].push(metric.value);
    }
    
    // Aggregate
    const results: Record<string, number> = {};
    for (const [labelKey, values] of Object.entries(groups)) {
      switch (aggregation) {
        case 'sum':
          results[labelKey] = values.reduce((a, b) => a + b, 0);
          break;
        case 'avg':
          results[labelKey] = values.reduce((a, b) => a + b, 0) / values.length;
          break;
        case 'max':
          results[labelKey] = Math.max(...values);
          break;
        case 'min':
          results[labelKey] = Math.min(...values);
          break;
        case 'count':
          results[labelKey] = values.length;
          break;
      }
    }
    
    return results;
  }
}