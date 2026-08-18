import { defaultRegistry } from '../extractors/registry.js';
import { ExtractionResult } from '../extractors/base.js';

export interface WorkerTask<T = any> {
  id: string;
  type: 'DOCUMENT' | 'IMAGE_OCR';
  filePath: string;
  maxFileSizeMB?: number;
  metadata?: Record<string, any>;
  execute?: () => Promise<T>;
}

export interface WorkerPoolConfig {
  maxConcurrentParsers?: number;
  maxConcurrentOCR?: number;
  taskTimeoutMs?: number;
}

export interface WorkerTaskResult {
  taskId: string;
  filePath: string;
  success: boolean;
  extraction?: ExtractionResult;
  error?: string;
  processingTimeMs: number;
  isOcr: boolean;
}

export class WorkerPool {
  private maxConcurrentParsers: number;
  private maxConcurrentOCR: number;
  private taskTimeoutMs: number;

  private activeDocWorkers = 0;
  private activeOcrWorkers = 0;
  private queue: WorkerTask[] = [];
  private isPaused = false;
  private activeTasks: Map<string, { startTime: number; timer: NodeJS.Timeout }> = new Map();

  constructor(config?: WorkerPoolConfig) {
    this.maxConcurrentParsers = config?.maxConcurrentParsers || 4;
    this.maxConcurrentOCR = config?.maxConcurrentOCR || 2;
    this.taskTimeoutMs = config?.taskTimeoutMs || 30_000;
  }

  public getStats() {
    return {
      activeDocWorkers: this.activeDocWorkers,
      activeOcrWorkers: this.activeOcrWorkers,
      maxDocWorkers: this.maxConcurrentParsers,
      maxOcrWorkers: this.maxConcurrentOCR,
      queueLength: this.queue.length,
      isPaused: this.isPaused
    };
  }

  public pause(): void {
    this.isPaused = true;
  }

  public resume(): void {
    this.isPaused = false;
    this.pump();
  }

  public clear(): void {
    this.queue = [];
  }

  public enqueue(task: WorkerTask): void {
    this.queue.push(task);
    this.pump();
  }

  public async runTask(task: WorkerTask): Promise<WorkerTaskResult> {
    const startTime = Date.now();
    const isOcr = task.type === 'IMAGE_OCR';

    // Wait until concurrency slot is free
    while (
      (isOcr && this.activeOcrWorkers >= this.maxConcurrentOCR) ||
      (!isOcr && this.activeDocWorkers >= this.maxConcurrentParsers) ||
      this.isPaused
    ) {
      await new Promise(resolve => setTimeout(resolve, 20));
    }

    if (isOcr) {
      this.activeOcrWorkers++;
    } else {
      this.activeDocWorkers++;
    }

    try {
      const timeoutPromise = new Promise<never>((_, reject) => {
        const timer = setTimeout(() => {
          reject(new Error(`Worker task timed out after ${this.taskTimeoutMs}ms for file '${task.filePath}'`));
        }, this.taskTimeoutMs);
        this.activeTasks.set(task.id, { startTime, timer });
      });

      const execPromise = (async () => {
        if (task.execute) {
          return await task.execute();
        }
        return await defaultRegistry.extract(task.filePath, task.maxFileSizeMB || 50);
      })();

      const extraction = await Promise.race([execPromise, timeoutPromise]);
      const taskMeta = this.activeTasks.get(task.id);
      if (taskMeta) {
        clearTimeout(taskMeta.timer);
        this.activeTasks.delete(task.id);
      }

      return {
        taskId: task.id,
        filePath: task.filePath,
        success: !extraction.metadata?.error,
        extraction,
        processingTimeMs: Date.now() - startTime,
        isOcr
      };
    } catch (err: any) {
      const taskMeta = this.activeTasks.get(task.id);
      if (taskMeta) {
        clearTimeout(taskMeta.timer);
        this.activeTasks.delete(task.id);
      }
      return {
        taskId: task.id,
        filePath: task.filePath,
        success: false,
        error: err.message || 'Worker processing failure',
        processingTimeMs: Date.now() - startTime,
        isOcr
      };
    } finally {
      if (isOcr) {
        this.activeOcrWorkers = Math.max(0, this.activeOcrWorkers - 1);
      } else {
        this.activeDocWorkers = Math.max(0, this.activeDocWorkers - 1);
      }
      this.pump();
    }
  }

  private pump(): void {
    if (this.isPaused || this.queue.length === 0) return;

    // Check if any slot is available
    const canDoc = this.activeDocWorkers < this.maxConcurrentParsers;
    const canOcr = this.activeOcrWorkers < this.maxConcurrentOCR;

    if (!canDoc && !canOcr) return;

    const taskIndex = this.queue.findIndex(t => 
      (t.type === 'IMAGE_OCR' && canOcr) || (t.type !== 'IMAGE_OCR' && canDoc)
    );

    if (taskIndex >= 0) {
      const [nextTask] = this.queue.splice(taskIndex, 1);
      this.runTask(nextTask).catch(() => {});
    }
  }
}
