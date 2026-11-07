import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    setupFiles: ["test/setup.ts"],
    fileParallelism: false, // each test file shares the in-memory DB module instance; keep them sequential
  },
});
