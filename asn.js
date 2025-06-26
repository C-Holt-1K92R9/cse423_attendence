const https = require('https');

// Function to get ISP info for current IP
function getISP() {
    https.get('https://api.ipify.org?format=json', (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
            const ip = JSON.parse(data).ip;
            https.get(`https://ipinfo.io/${ip}/json`, (res2) => {
                let data2 = '';
                res2.on('data', chunk => data2 += chunk);
                res2.on('end', () => {
                    const info = JSON.parse(data2);
                    if (info.org) {
                        // org is usually like "AS15169 Google LLC"
                        const isp = info.org.split(' ').slice(1).join(' ');
                        console.log('IP Address:', ip);
                        console.log('ISP Provider:', isp);
                    } else {
                        console.log('IP Address:', ip);
                        console.log('ISP info not found.');
                    }
                });
            }).on('error', err => {
                console.error('Error fetching ISP info:', err.message);
            });
        });
    }).on('error', err => {
        console.error('Error fetching IP:', err.message);
    });
}

getISP();