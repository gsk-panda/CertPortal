'use strict';

const axios = require('axios');

/** Cloudflare DNS plugin. credentials: { api_token } */
class CloudflareProvider {
  constructor(credentials) {
    this.http = axios.create({
      baseURL: 'https://api.cloudflare.com/client/v4',
      headers: { authorization: `Bearer ${credentials.api_token}` },
      timeout: 15000,
    });
  }

  async findZone(name) {
    const labels = name.replace(/\.$/, '').split('.');
    for (let i = 0; i < labels.length - 1; i++) {
      const candidate = labels.slice(i).join('.');
      const res = await this.http.get('/zones', { params: { name: candidate, status: 'active' } });
      if (res.data.success && res.data.result.length) return res.data.result[0];
    }
    throw new Error(`No Cloudflare zone found for ${name}`);
  }

  async createTxtRecord(name, value) {
    const zone = await this.findZone(name);
    const res = await this.http.post(`/zones/${zone.id}/dns_records`, {
      type: 'TXT', name, content: value, ttl: 60,
    });
    if (!res.data.success) throw new Error(`Cloudflare create TXT failed: ${JSON.stringify(res.data.errors)}`);
  }

  async deleteTxtRecord(name, value) {
    const zone = await this.findZone(name);
    const list = await this.http.get(`/zones/${zone.id}/dns_records`, { params: { type: 'TXT', name } });
    for (const rec of list.data.result || []) {
      if (rec.content === value || rec.content === `"${value}"`) {
        await this.http.delete(`/zones/${zone.id}/dns_records/${rec.id}`);
      }
    }
  }

  async test() {
    const res = await this.http.get('/zones', { params: { per_page: 1 } });
    if (!res.data.success) throw new Error(`Cloudflare API error: ${JSON.stringify(res.data.errors)}`);
    return `OK — token valid, ${res.data.result_info ? res.data.result_info.total_count : '?'} zone(s) visible`;
  }
}

module.exports = { CloudflareProvider };
