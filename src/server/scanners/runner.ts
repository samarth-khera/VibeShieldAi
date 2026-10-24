import { spawn, type ChildProcess } from "node:child_process";
import { mkdir } from "node:fs/promises";
import path from "node:path";
import { redactText } from "./redact";

export type SubprocessOptions = {
  cwd: string;
  timeoutMs?: number;
  maxBufferBytes?: number;
  allowedExitCodes?: number[];
  env?: Record<string, string>;
};

export type SubprocessResult = {
  stdout: string;
  stderr: string;
  exitCode: number;
  durationMs: number;
};

// Safe minimal environment for scanner subprocesses. Never leak DB, app tokens, or host user files.
export async function getCleanEnv(cwd: string, extraEnv?: Record<string, string>): Promise<NodeJS.ProcessEnv> {
  // Sandbox directories isolated from host user's actual $HOME
  const sandboxHome = path.join(cwd, ".sandbox_home");
  const sandboxTmp = path.join(cwd, ".sandbox_tmp");

  await mkdir(sandboxHome, { recursive: true, mode: 0o700 }).catch(() => undefined);
  await mkdir(sandboxTmp, { recursive: true, mode: 0o700 }).catch(() => undefined);

  return {
    PATH: process.env.PATH || "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
    HOME: sandboxHome,
    TMPDIR: sandboxTmp,
    USER: "scanner",
    LOGNAME: "scanner",
    LANG: "en_US.UTF-8",
    LC_ALL: "en_US.UTF-8",
    NODE_ENV: (process.env.NODE_ENV || "production") as "development" | "production" | "test",
    ...extraEnv,
  };
}

/**
 * Kills a child process and its entire process tree if supported.
 */
export function killProcessTree(child: ChildProcess): void {
  if (child.pid == null || child.killed) return;
  try {
    if (process.platform !== "win32") {
      // Negative PID targets the entire process group created via detached: true
      process.kill(-child.pid, "SIGKILL");
    } else {
      child.kill("SIGKILL");
    }
  } catch {
    try {
      child.kill("SIGKILL");
    } catch {
      // Process already terminated
    }
  }
}

/**
 * Runs an external CLI binary safely with process tree isolation, strict timeouts,
 * bounded output buffers, sanitized error snippets and an isolated sandbox home.
 */
export async function runSubprocess(
  binary: string,
  args: string[],
  options: SubprocessOptions,
): Promise<SubprocessResult> {
  const timeout = options.timeoutMs ?? 60_000;
  const maxBuffer = options.maxBufferBytes ?? 10 * 1024 * 1024; // 10MB default
  const allowedCodes = new Set(options.allowedExitCodes ?? [0]);

  const cleanEnv = await getCleanEnv(options.cwd, options.env);
  const startTime = Date.now();

  return new Promise<SubprocessResult>((resolve, reject) => {
    let child: ChildProcess;
    try {
      child = spawn(binary, args, {
        cwd: options.cwd,
        env: cleanEnv,
        detached: process.platform !== "win32",
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (err) {
      return reject(
        new Error(`Failed to spawn scanner binary "${binary}": ${err instanceof Error ? err.message : String(err)}`),
      );
    }

    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let timedOut = false;
    let bufferExceeded = false;
    let timer: NodeJS.Timeout | null = null;

    if (timeout > 0) {
      timer = setTimeout(() => {
        timedOut = true;
        try {
          if (process.platform !== "win32" && child.pid) {
            process.kill(-child.pid, "SIGTERM");
          } else {
            child.kill("SIGTERM");
          }
        } catch {
          // ignore
        }
        // Grace period before hard kill
        setTimeout(() => killProcessTree(child), 300).unref();
      }, timeout);
    }

    child.stdout?.on("data", (chunk: Buffer) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes + stderrBytes > maxBuffer) {
        bufferExceeded = true;
        killProcessTree(child);
        return;
      }
      stdoutChunks.push(chunk);
    });

    child.stderr?.on("data", (chunk: Buffer) => {
      stderrBytes += chunk.length;
      if (stdoutBytes + stderrBytes > maxBuffer) {
        bufferExceeded = true;
        killProcessTree(child);
        return;
      }
      stderrChunks.push(chunk);
    });

    child.on("error", (err) => {
      if (timer) clearTimeout(timer);
      killProcessTree(child);
      reject(new Error(`Scanner execution failed: ${err.message}`));
    });

    child.on("close", (code, signal) => {
      if (timer) clearTimeout(timer);
      const durationMs = Date.now() - startTime;

      if (bufferExceeded) {
        return reject(
          new Error(`Scanner output exceeded maximum buffer limit (${Math.round(maxBuffer / 1024 / 1024)}MB).`),
        );
      }

      if (timedOut || signal === "SIGTERM" || signal === "SIGKILL") {
        return reject(new Error(`Scanner timed out after ${timeout}ms.`));
      }

      const stdout = Buffer.concat(stdoutChunks).toString("utf8");
      const stderr = Buffer.concat(stderrChunks).toString("utf8");
      const exitCode = code ?? -1;

      if (allowedCodes.has(exitCode)) {
        return resolve({
          stdout,
          stderr,
          exitCode,
          durationMs,
        });
      }

      const rawSnippet = (stderr || stdout).trim().slice(0, 300);
      const sanitized = redactText(rawSnippet);
      reject(new Error(sanitized || `Scanner process exited with code ${exitCode}`));
    });
  });
}
