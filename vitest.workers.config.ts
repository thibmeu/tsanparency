import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [cloudflareTest({ miniflare: { compatibilityDate: "2026-08-01" } })],
  test: {
    include: ["test/**/*.test.ts"],
    testTimeout: 60_000,
    // One shared workerd isolate instead of one per file
    isolate: false,
  },
});
