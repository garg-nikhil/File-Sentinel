import { DatabaseSync } from 'node:sqlite';
import { ProtectedLicenseStore } from './protectedLicenseStore.js';

export class ClockMonitorService {
  private db: DatabaseSync;
  private timerInterval: NodeJS.Timeout | null = null;
  private lastSystemTime: number;
  private lastMonotonicTime: number;
  private startSystemTime: number;
  private startMonotonicTime: number;

  private driftThresholdMs: number; // e.g. 10000 (10 seconds)
  private checkIntervalMs: number;  // e.g. 5000 (5 seconds)
  private protectedStorePath?: string;

  constructor(
    db: DatabaseSync,
    options?: {
      driftThresholdMs?: number;
      checkIntervalMs?: number;
      protectedStorePath?: string;
    }
  ) {
    this.db = db;
    this.driftThresholdMs = options?.driftThresholdMs || 10000;
    this.checkIntervalMs = options?.checkIntervalMs || 5000;
    this.protectedStorePath = options?.protectedStorePath;

    this.lastSystemTime = Date.now();
    this.lastMonotonicTime = this.getMonotonicMs();
    this.startSystemTime = this.lastSystemTime;
    this.startMonotonicTime = this.lastMonotonicTime;
  }

  private getMonotonicMs(): number {
    if (typeof process !== 'undefined' && process.hrtime && process.hrtime.bigint) {
      return Number(process.hrtime.bigint() / 1_000_000n);
    }
    return performance.now();
  }

  /**
   * Start the clock drift background monitor
   */
  public start(onRollbackDetected?: (reason: string) => void): void {
    if (this.timerInterval) return;

    console.log(`[ClockMonitor] Starting system clock drift monitor. Check interval: ${this.checkIntervalMs}ms, Drift threshold: ${this.driftThresholdMs}ms`);

    this.timerInterval = setInterval(() => {
      this.checkClock(onRollbackDetected);
    }, this.checkIntervalMs);
  }

  /**
   * Stop the clock drift monitor
   */
  public stop(): void {
    if (this.timerInterval) {
      clearInterval(this.timerInterval);
      this.timerInterval = null;
    }
  }

  /**
   * Performs the clock drift and rollback verification
   */
  public checkClock(onRollbackDetected?: (reason: string) => void): void {
    const currentSystemTime = Date.now();
    const currentMonotonicTime = this.getMonotonicMs();

    const systemDelta = currentSystemTime - this.lastSystemTime;
    const monotonicDelta = currentMonotonicTime - this.lastMonotonicTime;

    let rollbackReason: string | null = null;

    // 1. Backwards progress check: system time should never move backwards compared to last check
    if (systemDelta < -2000) { // allowing 2s for minor OS clock synchronization/jitter
      rollbackReason = `System clock moved backward by ${Math.abs(systemDelta)}ms since last tick.`;
    }

    // 2. Relative drift check: compare elapsed system time vs monotonic elapsed time
    if (!rollbackReason) {
      const startSystemElapsed = currentSystemTime - this.startSystemTime;
      const startMonotonicElapsed = currentMonotonicTime - this.startMonotonicTime;
      const totalDrift = Math.abs(startSystemElapsed - startMonotonicElapsed);

      if (totalDrift > this.driftThresholdMs) {
        rollbackReason = `Excessive system clock drift detected: system elapsed = ${startSystemElapsed}ms, monotonic elapsed = ${startMonotonicElapsed}ms (drift = ${totalDrift}ms).`;
      }
    }

    // 3. Monotonic database/file check: system time must not be before last trusted or max seen timestamps
    if (!rollbackReason) {
      try {
        const store = new ProtectedLicenseStore(this.protectedStorePath);
        const state = store.loadState();
        if (state) {
          // Compare against max seen timestamp in the OS protected store
          if (state.maxSeenTimestampIso) {
            const maxSeenMs = new Date(state.maxSeenTimestampIso).getTime();
            // Allow standard tolerance of 1 hour (3600000ms) for timezones or minor NTP corrections
            if (!isNaN(maxSeenMs) && currentSystemTime < (maxSeenMs - 3600000)) {
              rollbackReason = `System time (${new Date(currentSystemTime).toISOString()}) is significantly behind last max seen trusted time (${state.maxSeenTimestampIso}).`;
            }
          }
        }

        // Compare against last_trusted_timestamp in database
        const dbRow = this.db.prepare(
          'SELECT last_trusted_timestamp FROM license_state ORDER BY last_trusted_timestamp DESC LIMIT 1'
        ).get() as { last_trusted_timestamp: string } | undefined;

        if (dbRow && dbRow.last_trusted_timestamp) {
          const dbMaxMs = new Date(dbRow.last_trusted_timestamp).getTime();
          if (!isNaN(dbMaxMs) && currentSystemTime < (dbMaxMs - 3600000)) {
            rollbackReason = `System time (${new Date(currentSystemTime).toISOString()}) is significantly behind database trusted time (${dbRow.last_trusted_timestamp}).`;
          }
        }
      } catch (err: any) {
        // Suppress warning if license table is empty or does not exist yet
      }
    }

    if (rollbackReason) {
      console.error('[ClockMonitor] CLOCK_ROLLBACK_DETECTED:', rollbackReason);
      this.triggerClockRollback(rollbackReason, onRollbackDetected);
    } else {
      // Update tracking values for next tick
      this.lastSystemTime = currentSystemTime;
      this.lastMonotonicTime = currentMonotonicTime;
    }
  }

  /**
   * Persistently blocks scanning by triggering the CLOCK_ROLLBACK_DETECTED state
   */
  public triggerClockRollback(reason: string, onRollbackDetected?: (reason: string) => void): void {
    const nowIso = new Date().toISOString();

    // 1. Update OS-protected store if possible
    try {
      const store = new ProtectedLicenseStore(this.protectedStorePath);
      const state = store.loadState();
      if (state) {
        store.saveState({
          ...state,
          clockRollbackDetected: true,
          status: 'CLOCK_ROLLBACK_DETECTED',
          updatedAtIso: nowIso
        });
      }
    } catch (err: any) {
      console.error('[ClockMonitor] Failed to write rollback to OS-Protected Store:', err.message);
    }

    // 2. Update SQLite Database
    try {
      this.db.prepare(
        'UPDATE license_state SET clock_rollback_detected = 1, status = ?, updated_at = ?'
      ).run('CLOCK_ROLLBACK_DETECTED', nowIso);
    } catch (err: any) {
      // Suppress or log
    }

    // Stop checking since we have triggered the block state
    this.stop();

    if (onRollbackDetected) {
      onRollbackDetected(reason);
    }
  }
}
