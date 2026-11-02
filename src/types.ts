import { z } from "zod";

export interface ToolDef {
  name: string;
  description: string;
  schema: z.ZodObject<any>;
  handler: (args: any) => Promise<ToolResult>;
}

export interface ToolResult {
  content: Array<{ type: "text"; text: string } | { type: "image"; data: string; mimeType: string }>;
  isError?: boolean;
}

export const ok = (text: string | object): ToolResult => ({
  content: [{ type: "text", text: typeof text === "string" ? text : JSON.stringify(text, null, 2) }],
});

export const err = (message: string): ToolResult => ({
  content: [{ type: "text", text: `error: ${message}` }],
  isError: true,
});
