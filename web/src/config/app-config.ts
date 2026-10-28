import packageJson from "../../package.json";

const currentYear = new Date().getFullYear();

export const APP_CONFIG = {
  name: "Ning",
  version: packageJson.version,
  copyright: `© ${currentYear}, Ning.`,
  meta: {
    title: "Ning — Autonomous Penetration Testing Console",
    description: "Console for the LLM-driven autonomous penetration testing system",
  },
};
