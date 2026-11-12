export class ApiError extends Error {
  status: number;

  constructor(status: number, detail: string) {
    super(detail);
    this.status = status;
  }
}

async function parseError(response: Response): Promise<never> {
  let detail = `请求失败（HTTP ${response.status}）`;
  try {
    const body = await response.json();
    if (typeof body?.detail === 'string') detail = body.detail;
    else if (body?.detail) detail = JSON.stringify(body.detail);
  } catch {
    // keep the generic message
  }
  throw new ApiError(response.status, detail);
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, init);
  if (!response.ok) await parseError(response);
  return (await response.json()) as T;
}

export function getJson<T>(path: string, params?: Record<string, string | number | boolean | undefined>): Promise<T> {
  const search = new URLSearchParams();
  Object.entries(params || {}).forEach(([key, value]) => {
    if (value !== undefined && value !== '') search.set(key, String(value));
  });
  const query = search.toString();
  return request<T>(query ? `${path}?${query}` : path);
}

export function postJson<T>(path: string, body: unknown): Promise<T> {
  return request<T>(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

export function patchJson<T>(path: string, body: unknown): Promise<T> {
  return request<T>(path, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

export function postFiles<T>(path: string, files: Record<string, File>, data: Record<string, string | undefined>): Promise<T> {
  const form = new FormData();
  Object.entries(files).forEach(([key, file]) => form.append(key, file));
  Object.entries(data).forEach(([key, value]) => {
    if (value !== undefined) form.append(key, value);
  });
  return request<T>(path, { method: 'POST', body: form });
}
