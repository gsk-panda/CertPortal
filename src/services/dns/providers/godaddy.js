'use strict';

const axios = require('axios');

/** GoDaddy DNS plugin. credentials: { api_key, api_secret } */
class GoDaddyProvider {
  constructor(credentials) {
    this.http = axios.create({
      baseURL: 'https://api.godaddy.com/v1',
      headers: { authorization: `sso-key ${credentials.api_key}:${credentials.api_secret}` },
      timeout: 15000,
      validateStatus: () => true,
    });
  }

  async findDomain(name) {
    const labels = name.replace(/\.$/, '').split('.');
    for (let i = 0; i < labels.length - 1; i++) {
      const candidate = labels.slice(i).join('.');
      const res = await this.http.get(`/domains/${candidate}`);
      if (res.status === 200) return candidate;
    }
    throw new Error(`No GoDaddy domain found for ${name}`);
  }

  async createTxtRecord(name, value) {
    const domain = await this.findDomain(name);
    const rel = name.slice(0, -(domain.length + 1)) || '@';
    const res = await this.http.patch(`/domains/${domain}/records`, [
      { type: 'TXT', name: rel, data: value, ttl: 600 },
    ]);
    if (res.status >= 400) throw new Error(`GoDaddy create TXT failed (${res.status}): ${JSON.stringify(res.data)}`);
  }

  async deleteTxtRecord(name, value) {
    const domain = await this.findDomain(name);
    const rel = name.slice(0, -(domain.length + 1)) || '@';
    const res = await this.http.get(`/domains/${domain}/records/TXT/${rel}`);
    if (res.status !== 200) return;
    const remaining = (res.data || []).filter((r) => r.data !== value);
    if (remaining.length) {
      await this.http.put(`/domains/${domain}/records/TXT/${rel}`, remaining);
    } else {
      await this.http.delete(`/domains/${domain}/records/TXT/${rel}`);
    }
  }

  async test() {
    const res = await this.http.get('/domains', { params: { limit: 1 } });
    if (res.status >= 400) throw new Error(`GoDaddy API error ${res.status}: ${JSON.stringify(res.data)}`);
    return 'OK — API key valid';
  }
}

module.exports = { GoDaddyProvider };
