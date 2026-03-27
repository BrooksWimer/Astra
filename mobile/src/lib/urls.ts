import { Linking, NativeModules } from "react-native";

export function normalizeBaseUrl(raw: string, defaultPort?: string): string {
  let value = raw.trim();
  if (!value) return "";

  if (!/^https?:\/\//i.test(value)) {
    value = `http://${value}`;
  }

  try {
    const url = new URL(value);
    if (defaultPort && !url.port) {
      url.port = defaultPort;
    }
    url.pathname = "";
    url.search = "";
    url.hash = "";
    return url.toString().replace(/\/$/, "");
  } catch {
    return value.replace(/\/+$/, "");
  }
}

export function deriveAdviceBaseUrl(agentBaseUrl: string): string | null {
  try {
    const url = new URL(agentBaseUrl);
    url.port = "3000";
    url.pathname = "";
    url.search = "";
    url.hash = "";
    return url.toString().replace(/\/$/, "");
  } catch {
    return null;
  }
}

function getBundlerScriptUrl(): string | null {
  const sourceCode = NativeModules.SourceCode as { scriptURL?: string } | undefined;
  return typeof sourceCode?.scriptURL === "string" ? sourceCode.scriptURL : null;
}

function getHostFromUrl(raw: string | null | undefined): string | null {
  if (!raw) {
    return null;
  }

  try {
    const url = new URL(raw);
    return url.hostname || null;
  } catch {
    return null;
  }
}

function getNestedBundleUrl(raw: string | null | undefined): string | null {
  if (!raw) {
    return null;
  }

  try {
    const url = new URL(raw);
    return url.searchParams.get("url");
  } catch {
    return null;
  }
}

export function getDetectedDevHost(): string | null {
  const scriptUrl = getBundlerScriptUrl();
  return getHostFromUrl(scriptUrl);
}

export function getDetectedServiceBaseUrl(port: string): string {
  const host = getDetectedDevHost();

  if (!host) {
    return "";
  }

  const url = new URL("http://localhost");
  url.hostname = host;
  url.port = port;
  url.pathname = "";
  url.search = "";
  url.hash = "";
  return url.toString().replace(/\/$/, "");
}

export async function detectDevHostAsync(): Promise<string | null> {
  const initialUrl = await Linking.getInitialURL();
  const nestedBundleUrl = getNestedBundleUrl(initialUrl);

  return (
    getHostFromUrl(nestedBundleUrl) ||
    getHostFromUrl(initialUrl) ||
    getDetectedDevHost()
  );
}

export async function detectServiceBaseUrlAsync(port: string): Promise<string> {
  const host = await detectDevHostAsync();

  if (!host) {
    return "";
  }

  const url = new URL("http://localhost");
  url.hostname = host;
  url.port = port;
  url.pathname = "";
  url.search = "";
  url.hash = "";
  return url.toString().replace(/\/$/, "");
}
