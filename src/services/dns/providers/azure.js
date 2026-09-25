'use strict';

const axios = require('axios');

/**
 * Azure DNS plugin (service principal).
 * credentials: { tenant_id, client_id, client_secret, subscription_id, resource_group }
 */
class AzureDnsProvider {
  constructor(credentials) {
    this.c = credentials;
    this.token = null;
    this.tokenExp = 0;
  }

  async getToken() {
    if (this.token && Date.now() < this.tokenExp - 60000) return this.token;
    const res = await axios.post(
      `https://login.microsoftonline.com/${this.c.tenant_id}/oauth2/v2.0/token`,
      new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: this.c.client_id,
        client_secret: this.c.client_secret,
        scope: 'https://management.azure.com/.default',
      }).toString(),
      { headers: { 'content-type': 'application/x-www-form-urlencoded' }, timeout: 15000 }
    );
    this.token = res.data.access_token;
    this.tokenExp = Date.now() + res.data.expires_in * 1000;
    return this.token;
  }

  async api(method, path, data) {
    const token = await this.getToken();
    const res = await axios({
      method,
      url: `https://management.azure.com${path}?api-version=2018-05-01`,
      data,
      headers: { authorization: `Bearer ${token}` },
      timeout: 15000,
      validateStatus: () => true,
    });
    if (res.status >= 400 && res.status !== 404) {
      throw new Error(`Azure DNS API ${method} ${path} -> ${res.status}: ${JSON.stringify(res.data && res.data.error && res.data.error.message)}`);
    }
    return res;
  }

  zonesBase() {
    return `/subscriptions/${this.c.subscription_id}/resourceGroups/${this.c.resource_group}/providers/Microsoft.Network/dnsZones`;
  }

  async findZone(name) {
    const res = await this.api('get', this.zonesBase());
    const zones = (res.data.value || []).map((z) => z.name);
    const target = name.replace(/\.$/, '');
    let best = null;
    for (const z of zones) {
      if ((target === z || target.endsWith('.' + z)) && (!best || z.length > best.length)) best = z;
    }
    if (!best) throw new Error(`No Azure DNS zone found for ${name} in resource group ${this.c.resource_group}`);
    return best;
  }

  relative(name, zone) {
    const rel = name.replace(/\.$/, '').slice(0, -(zone.length + 1));
    return rel || '@';
  }

  async createTxtRecord(name, value) {
    const zone = await this.findZone(name);
    const rel = this.relative(name, zone);
    const path = `${this.zonesBase()}/${zone}/TXT/${rel}`;
    const existing = await this.api('get', path);
    const records = existing.status === 200 ? (existing.data.properties.TXTRecords || []) : [];
    records.push({ value: [value] });
    await this.api('put', path, { properties: { TTL: 60, TXTRecords: records } });
  }

  async deleteTxtRecord(name, value) {
    const zone = await this.findZone(name);
    const rel = this.relative(name, zone);
    const path = `${this.zonesBase()}/${zone}/TXT/${rel}`;
    const existing = await this.api('get', path);
    if (existing.status !== 200) return;
    const records = (existing.data.properties.TXTRecords || []).filter((r) => !(r.value || []).includes(value));
    if (records.length) await this.api('put', path, { properties: { TTL: 60, TXTRecords: records } });
    else await this.api('delete', path);
  }

  async test() {
    const res = await this.api('get', this.zonesBase());
    return `OK — service principal valid, ${(res.data.value || []).length} zone(s) in ${this.c.resource_group}`;
  }
}

module.exports = { AzureDnsProvider };
