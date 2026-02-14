type EndpointName = "resolve" | "anchor" | "supersede";

type Bucket = {
  windowStartMs: number;
  count: number;
};

const limits: Record<EndpointName, number> = {
  resolve: 60,
  anchor: 20,
  supersede: 20
};

const buckets = new Map<string, Bucket>();

export function checkRateLimit(projectId: string, endpoint: EndpointName): boolean {
  const now = Date.now();
  const windowStartMs = now - (now % 60000);
  const key = `${projectId}:${endpoint}`;

  const current = buckets.get(key);
  if (!current || current.windowStartMs !== windowStartMs) {
    buckets.set(key, { windowStartMs, count: 1 });
    return true;
  }

  if (current.count >= limits[endpoint]) {
    return false;
  }

  current.count += 1;
  buckets.set(key, current);
  return true;
}
