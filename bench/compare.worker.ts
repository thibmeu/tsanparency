import { compare } from "./compare.ts";

export default {
  async fetch(): Promise<Response> {
    const lines: string[] = [];
    await compare((line) => lines.push(line));
    return new Response(lines.join("\n"));
  },
};
