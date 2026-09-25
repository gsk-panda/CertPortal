'use strict';

const {
  Route53Client,
  ListHostedZonesCommand,
  ChangeResourceRecordSetsCommand,
  ListResourceRecordSetsCommand,
} = require('@aws-sdk/client-route-53');

/**
 * AWS Route53 plugin. credentials: { access_key_id, secret_access_key, region? }
 * Leave keys empty to use the instance role / default provider chain.
 */
class Route53Provider {
  constructor(credentials) {
    const cfg = { region: credentials.region || 'us-east-1' };
    if (credentials.access_key_id && credentials.secret_access_key) {
      cfg.credentials = {
        accessKeyId: credentials.access_key_id,
        secretAccessKey: credentials.secret_access_key,
      };
    }
    this.client = new Route53Client(cfg);
  }

  async findZone(name) {
    const res = await this.client.send(new ListHostedZonesCommand({}));
    const target = name.replace(/\.$/, '') + '.';
    let best = null;
    for (const z of res.HostedZones || []) {
      if (z.Config && z.Config.PrivateZone) continue;
      if (target.endsWith(z.Name) && (!best || z.Name.length > best.Name.length)) best = z;
    }
    if (!best) throw new Error(`No Route53 hosted zone found for ${name}`);
    return best;
  }

  async change(action, name, values) {
    const zone = await this.findZone(name);
    await this.client.send(new ChangeResourceRecordSetsCommand({
      HostedZoneId: zone.Id,
      ChangeBatch: {
        Changes: [{
          Action: action,
          ResourceRecordSet: {
            Name: name + '.',
            Type: 'TXT',
            TTL: 60,
            ResourceRecords: values.map((v) => ({ Value: `"${v}"` })),
          },
        }],
      },
    }));
  }

  async currentValues(name) {
    const zone = await this.findZone(name);
    const res = await this.client.send(new ListResourceRecordSetsCommand({
      HostedZoneId: zone.Id, StartRecordName: name + '.', StartRecordType: 'TXT', MaxItems: 1,
    }));
    const set = (res.ResourceRecordSets || []).find((s) => s.Name === name + '.' && s.Type === 'TXT');
    return set ? set.ResourceRecords.map((r) => r.Value.replace(/^"|"$/g, '')) : [];
  }

  // Route53 TXT sets are single objects holding all values: merge on create.
  async createTxtRecord(name, value) {
    const existing = await this.currentValues(name);
    await this.change('UPSERT', name, [...new Set([...existing, value])]);
  }

  async deleteTxtRecord(name, value) {
    const existing = await this.currentValues(name);
    const remaining = existing.filter((v) => v !== value);
    if (!existing.length) return;
    if (remaining.length) await this.change('UPSERT', name, remaining);
    else await this.change('DELETE', name, existing);
  }

  async test() {
    const res = await this.client.send(new ListHostedZonesCommand({ MaxItems: 100 }));
    return `OK — credentials valid, ${(res.HostedZones || []).length} hosted zone(s) visible`;
  }
}

module.exports = { Route53Provider };
