// Mock switch. A public variable injected at build time (only the NEXT_PUBLIC_ prefix is readable in the browser).
// On Vercel, setting NEXT_PUBLIC_MOCK=1 runs the whole site on mock with no backend needed.
export const MOCK = process.env.NEXT_PUBLIC_MOCK === "1";

// MOCK_CLEAN=1：mock 层保留（接口形状、兜底能力不动），但**清空所有演示数据**。
// 用于"干净的 ARGUS"：还没有接入真实后端的页面显示空状态，而不是 acme.com 那套假数据。
export const MOCK_CLEAN = process.env.NEXT_PUBLIC_MOCK_CLEAN === "1";
