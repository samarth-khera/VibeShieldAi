import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

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

// Safe minimal environment for scanner subprocesses. Never leak DB or app tokens.
function getCleanEnv(extraEnv?: Record<string, string>): NodeJS.ProcessEnv {
  return {
    PATH: process.env.PATH || "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
    HOME: process.env.HOME || "/tmp",
    TMPDIR: process.env.TMPDIR || "/tmp",
    LANG: "en_US.UTF-8",
    LC_ALL: "en_US.UTF-8",
    NODE_ENV: (process.env.NODE_ENV || "production") as "development" | "production" | "test",
    ...extraEnv,
  };
}

/**
 * Runs an external CLI binary safely with strict timeouts, resource limits and isolated environment.
 */
export async function runSubprocess(
  binary: string,
  args: string[],
  options: SubprocessOptions,
): Promise<SubprocessResult> {
  const timeout = options.timeoutMs ?? 60_000;
  const maxBuffer = options.maxBufferBytes ?? 10 * 1024 * 1024; // 10MB
  const allowedCodes = new Set(options.allowedExitCodes ?? [0]);

  const startTime = Date.now();

  try {
    const { stdout, stderr } = await execFileAsync(binary, args, {
      cwd: options.cwd,
      timeout,
      maxBuffer,
      env: getCleanEnv(options.env),
      killSignal: "SIGKILL",
    });

    return {
      stdout: stdout.toString(),
      stderr: stderr.toString(),
      exitCode: 0,
      durationMs: Date.now() - startTime,
    };
  } catch (err: unknown) {
    const durationMs = Date.now() - startTime;
    const error = err as {
      code?: number | string;
      stdout?: string | Buffer;
      stderr?: string | Buffer;
      killed?: boolean;
      signal?: string;
      message?: string;
    };

    if (error.killed || error.signal === "SIGTERM" || error.signal === "SIGKILL") {
      throw new Error(`Scanner timed out after ${timeout}ms.`);
    }

    const numericCode = typeof error.code === "number" ? error.code : -1;
    if (allowedCodes.has(numericCode)) {
      return {
        stdout: error.stdout?.toString() ?? "",
        stderr: error.stderr?.toString() ?? "",
        exitCode: numericCode,
        durationMs,
      };
    }

    const stderrSnippet = (error.stderr?.toString() ?? "").trim().slice(0, 300);
    throw new Error(stderrSnippet || error.message || `Scanner process exited with code ${error.code}`);
  }
}
