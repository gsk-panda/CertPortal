'use strict';

/**
 * Manual provider: no API. The issuance flow stores pending TXT records on
 * the certificate, the UI shows them, and issuance continues once the user
 * confirms + propagation is observed on authoritative nameservers.
 */
class ManualProvider {
  constructor() {
    this.manual = true;
  }

  async createTxtRecord() { /* the operator creates the record */ }
  async deleteTxtRecord() { /* the operator removes the record */ }

  async test() {
    return 'OK — manual mode: TXT records must be created by an operator at issuance time';
  }
}

module.exports = { ManualProvider };
