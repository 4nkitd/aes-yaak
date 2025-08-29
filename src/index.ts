import { PluginDefinition } from "@yaakapp/api";

/**
 * Bridge the TypeScript AES plugin (src/aesPlugin.ts) into Yaak's plugin entry point.
 *
 * We import the TS module directly and adapt its `templates` array into Yaak's
 * `templateFunctions` shape (adds lightweight arg metadata + onRender wrapper).
 *
 * This replaces the previous CommonJS bridge that required ./plugin.js.
 */
import aesTsPlugin from "./aesPlugin";

type AnyTemplate = {
  name: string;
  description?: string;
  args: string[];
  run: (ctx: any, ...args: any[]) => Promise<string> | string;
};

const aesTemplates: AnyTemplate[] = (aesTsPlugin?.templates ||
  []) as AnyTemplate[];

const templateFunctions = aesTemplates.map((t) => ({
  name: t.name,
  description: t.description,
  // Minimal arg metadata; Yaak expects objects derived from FormInput.
  args: t.args.map((arg) => ({
    name: arg,
    label: arg,
    type: "text" as const,
    required: false,
  })),
  async onRender(ctx: any, callArgs: any) {
    const values = callArgs?.values || {};
    const ordered = t.args.map((argName) => values[argName] ?? "");
    return await t.run(ctx, ...ordered);
  },
}));

export const plugin: PluginDefinition = {
  httpRequestActions: [
    // {
    //   label: "Hello, From Plugin",
    //   icon: "info",
    //   async onSelect(ctx, args) {
    //     await ctx.toast.show({
    //       color: "success",
    //       message: `You clicked the request ${args.httpRequest.id}`,
    //     });
    //   },
    // },
    {
      label: "List AES Templates",
      icon: "info",
      async onSelect(ctx) {
        const names =
          (templateFunctions || []).map((t) => t.name).join(", ") || "(none)";
        await ctx.toast.show({
          color: names && names !== "(none)" ? "info" : "warning",
          message: `AES templates: ${names}`,
        });
      },
    },
  ],
  templateFunctions,
};

export default plugin;

// CommonJS compatibility: ensure templateFunctions reachable
// (Some loaders expect module.exports.templateFunctions)
if (typeof module !== "undefined") {
  // @ts-ignore
  module.exports = plugin;
  // @ts-ignore
  module.exports.plugin = plugin;
  // @ts-ignore
  module.exports.templateFunctions = plugin.templateFunctions;
  // @ts-ignore
  module.exports.default = plugin;
}
