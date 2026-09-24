const BASE_URL = '/api';

async function fetchJSON<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${url}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`);
  return res.json();
}

// Attacks
export const getAttacks = (category?: string) =>
  fetchJSON<any[]>(`/attacks${category ? `?category=${category}` : ''}`);

export const getCategories = () => fetchJSON<string[]>('/attacks/categories');

export const runAttack = (data: { type: string; target: any; params: any }) =>
  fetchJSON<any>('/attacks/run', { method: 'POST', body: JSON.stringify(data) });

// Campaigns
export const createCampaign = (data: any) =>
  fetchJSON<any>('/campaigns', { method: 'POST', body: JSON.stringify(data) });

export const getCampaign = (id: string) => fetchJSON<any>(`/campaigns/${id}`);

export const abortCampaign = (id: string) =>
  fetchJSON<any>(`/campaigns/${id}/abort`, { method: 'POST' });

// Reports
export const getReportFormats = (campaignId: string) =>
  fetchJSON<any>(`/reports/${campaignId}/formats`);
