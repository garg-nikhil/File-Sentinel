import { api } from './api';

export class ClientClockMonitor {
  private baselinePerformance: number;
  private baselineDate: number;
  private lastDateNow: number;
  private timer: number | null = null;
  private thresholdMs: number;
  private intervalMs: number;
  private tickCount: number;

  constructor(thresholdMs = 5000, intervalMs = 2000) {
    this.baselinePerformance = performance.now();
    this.baselineDate = Date.now();
    this.lastDateNow = this.baselineDate;
    this.thresholdMs = thresholdMs;
    this.intervalMs = intervalMs;
    this.tickCount = 0;
  }

  /**
   * Start the system clock monitoring observer loop
   */
  public start(onManipulationDetected: (reason: string) => void): void {
    if (this.timer) return;

    this.timer = window.setInterval(() => {
      const currentDateNow = Date.now();
      const currentPerformanceNow = performance.now();

      // Check 1: Direct backward adjustment
      if (currentDateNow < this.lastDateNow - 1000) { // 1 second minor tolerance
        const reason = `System clock moved backwards. Current: ${new Date(currentDateNow).toISOString()}, Previous: ${new Date(this.lastDateNow).toISOString()}`;
        
        // Log bad status heartbeat immediately before locking
        api.logClockMonitorHeartbeat({
          deltaMs: Math.abs(currentDateNow - this.lastDateNow),
          elapsedPerformanceMs: Math.round(currentPerformanceNow - this.baselinePerformance),
          elapsedDateMs: Math.round(currentDateNow - this.baselineDate),
          status: 'ROLLBACK_DETECTED'
        }).catch(() => {});

        onManipulationDetected(reason);
        this.stop();
        return;
      }

      // Check 2: Drift comparison against high-precision performance.now()
      const elapsedPerformance = currentPerformanceNow - this.baselinePerformance;
      const elapsedDate = currentDateNow - this.baselineDate;
      const delta = Math.abs(elapsedDate - elapsedPerformance);

      if (delta > this.thresholdMs) {
        const reason = `System clock manipulation detected! Baseline deviation: ${Math.round(delta)}ms (Date elapsed: ${Math.round(elapsedDate)}ms, Monotonic elapsed: ${Math.round(elapsedPerformance)}ms)`;
        
        // Log bad status heartbeat immediately before locking
        api.logClockMonitorHeartbeat({
          deltaMs: Math.round(delta),
          elapsedPerformanceMs: Math.round(elapsedPerformance),
          elapsedDateMs: Math.round(elapsedDate),
          status: 'DRIFT_EXCEEDED'
        }).catch(() => {});

        onManipulationDetected(reason);
        this.stop();
        return;
      }

      // Low-frequency heartbeat logger (every 30 seconds / 15 ticks)
      this.tickCount++;
      if (this.tickCount >= 15) {
        this.tickCount = 0;
        api.logClockMonitorHeartbeat({
          deltaMs: Math.round(delta),
          elapsedPerformanceMs: Math.round(elapsedPerformance),
          elapsedDateMs: Math.round(elapsedDate),
          status: 'HEALTHY'
        }).catch((err) => console.error('[ClockMonitor] Heartbeat log failed:', err));
      }

      this.lastDateNow = currentDateNow;
    }, this.intervalMs);
  }

  /**
   * Stop the system clock monitoring loop
   */
  public stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }
}
