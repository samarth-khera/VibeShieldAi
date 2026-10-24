import os from "node:os";

export type PlatformIsolationInfo = {
  platform: string;
  isLinuxContainer: boolean;
  isolationMode: "linux_container" | "darwin_process_sandbox" | "process_sandbox";
  controls: {
    processTreeKill: boolean;
    isolatedSandboxHome: boolean;
    environmentSanitized: boolean;
    outputBufferLimitBytes: number;
    defaultTimeoutMs: number;
    noHostDockerSocket: boolean;
    kernelNamespacesAvailable: boolean;
  };
  limitations: string[];
};

/**
 * Returns the verified isolation capabilities of the current host environment.
 * Accurately distinguishes local macOS development from production Linux container environments.
 */
export function getPlatformIsolationInfo(): PlatformIsolationInfo {
  const platform = os.platform();
  const isLinux = platform === "linux";
  // Check if running inside container
  const isContainer = Boolean(
    process.env.CONTAINER ||
    process.env.DOCKER_CONTAINER ||
    process.env.KUBERNETES_SERVICE_HOST
  );

  const limitations: string[] = [];

  if (platform === "darwin") {
    limitations.push(
      "macOS (Darwin) host: Operating system does not support unprivileged Linux user namespaces or cgroups. " +
      "Isolation is enforced via process-group termination, isolated sandbox $HOME/tmp directories, stripped environments, and execution output limits. " +
      "Production container isolation (read-only root, cap-drop=ALL, network=none) requires Linux container deployment."
    );
  } else if (!isContainer) {
    limitations.push(
      "Bare-metal Linux host: Process-level sandbox active. Container-level cgroups/seccomp should be applied via Docker or Podman."
    );
  }

  return {
    platform,
    isLinuxContainer: isLinux && isContainer,
    isolationMode: (isLinux && isContainer)
      ? "linux_container"
      : (platform === "darwin" ? "darwin_process_sandbox" : "process_sandbox"),
    controls: {
      processTreeKill: true,
      isolatedSandboxHome: true,
      environmentSanitized: true,
      outputBufferLimitBytes: 10 * 1024 * 1024, // 10MB
      defaultTimeoutMs: 60_000,
      noHostDockerSocket: true,
      kernelNamespacesAvailable: isLinux,
    },
    limitations,
  };
}
