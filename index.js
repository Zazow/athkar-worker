import jwt from '@tsndr/cloudflare-worker-jwt';

async function getJWTAccessToken(env) {
	const iat = Math.floor(Date.now() / 1000);
	const exp = iat + 3600;
	const jwtToken = jwt.sign(
		{
			iss: env.GOOGLE_SHEETS_SERVICE_ACCOUNT,
			scope: 'https://www.googleapis.com/auth/spreadsheets',
			aud: 'https://accounts.google.com/o/oauth2/token',
			exp,
			iat,
		},
		env.GOOGLE_SHEETS_PRIVATE_KEY,
		{ algorithm: 'RS256' }
	);
	return jwtToken;
}

async function getGoogleSheetsAccessToken(env) {
	const jwtToken = await getJWTAccessToken(env);
	const response = await fetch('https://accounts.google.com/o/oauth2/token', {
		method: 'POST',
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded',
		},
		body: new URLSearchParams({
			grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
			assertion: jwtToken,
		}),
	}).then(response => response.json());
	return response.access_token;
}

async function getAllRows(sheets, accessToken, env) {
    const rangesParam = sheets
      .map(range => `ranges=${encodeURIComponent(range)}`)
      .join('&');

		const response = await fetch(
			`https://sheets.googleapis.com/v4/spreadsheets/${env.GOOGLE_SHEETS_ID}/values:batchGet?${rangesParam}`, // /${env.GOOGLE_SHEETS_PAGE}`,
			{
				method: 'GET',
				headers: {
					'Authorization': `Bearer ${accessToken}`,
				},
			}
		);
		
		if (response.ok) {
			const res = await response.json();
      const data = {}
      for (let sheet of res.valueRanges) {
        if (sheet.values === undefined || sheet.values.length === 0) {
          continue;
        }
        const sheetName = sheet.range.split("!")[0];
        const header = sheet.values[0];
        const sheetData = []
        for (let i = 1; i < sheet.values.length; i++) {
          const row = {}
          for (let j = 0; j < header.length; j++) {
            row[header[j]] = sheet.values[i][j];
          }
          sheetData.push(row);
        }
        data[sheetName] = sheetData;
      }

			return {
				data: data, // Pull all rows as an array of arrays
				status: response.status,
			};
		} else {
			return {
				error: response.statusText,
				status: response.status,
			};
		}
}


export default {
	async fetch(request, env) {
    const accessToken = await getGoogleSheetsAccessToken(env);
    const rows = await getAllRows(["'Ayat'", "'Athkar'"], accessToken, env);
		return new Response(JSON.stringify(rows), {
			headers: {
				'Content-Type': 'application/json',
			},
		});
	},
};
