
import { parse } from 'csv-parse/sync'
import * as fs from 'node:fs'
import { loadX509FromPem } from '../utils/index.ts'

/**
 * SHA-256 fingerprints of roots that NSS no longer trusts for TLS,
 * but that CCADB still reports with the Websites trust bit.
 */
const EXCLUDED_ROOTS = [
	// eMudhra intermediate CA compromise, removed in NSS 3.131.1
	'86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B', // emSign ECC Root CA - G3
	'125609AA301DA0A249B97A8239CB6A34216F44DCAC9F3954B14292F2E8C8608F', // emSign Root CA - C1
	'BC4D809B15189D78DB3E1D8CF4F9726A795DA1643CA5F1358E1DDB0EDC0D7EB3', // emSign ECC Root CA - C3
]

async function main() {
	const resp = await fetch('https://ccadb.my.salesforce-sites.com/mozilla/IncludedCACertificateReportPEMCSV')
	const csv = await resp.text()
	const records = parse(csv, {
		columns: true,
		// eslint-disable-next-line camelcase
		skip_empty_lines: true

	})

	const data = fs.readFileSync('src/scripts/ca-template.ts', 'utf8')

	let certs = ''
	for(const record of records) {
		// only include roots trusted for TLS server authentication
		if(!record['Trust Bits'].split(';').includes('Websites')) {
			continue
		}

		if(EXCLUDED_ROOTS.includes(record['SHA-256 Fingerprint'])) {
			continue
		}

		let pem:string = record['PEM Info']
		pem = pem.slice(1, -1) //remove ' at the beginning and end
		pem = pem.replaceAll(/\s+\n/sgi, '\n') //remove trailing spaces in some certs

		//validate
		const cert = loadX509FromPem(pem)
		if(!cert.isWithinValidity()) {
			throw new Error('certificate is not within validity period')
		}

		pem = '`' + pem + '`, //' + record['Common Name or Certificate Name'] + '\n'

		certs += pem
	}

	const newData = data.replace('\'<<CERTIFICATES>>\'', certs)
	fs.writeFileSync('src/utils/mozilla-root-cas.ts', Buffer.from(newData))
}

main().then()