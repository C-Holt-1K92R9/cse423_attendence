const axios = require('axios');

const requestIp = "118.179.57.59";

(async () => {
  try {
    console.log('Fetching ISP info for IP:', requestIp);

    const response = await axios.get(`https://ipinfo.io/${requestIp}/json`);
    const info = response.data;

    let isp = '';
    if (info && info.org) {
      isp = info.org.split(' ').slice(1).join(' ');
    }
    console.log('ISP Provider:', isp || 'Not found');
  } catch (error) {
    console.error('Error verifying ISP:', error.message);
  }
})();
