# Vercel Deployment Guide

## Required Environment Variables on Vercel

You MUST set these variables in your Vercel project settings:

### Database Configuration
- `DB_HOST` - Your Aiven MySQL host (e.g., attendence-xxx.k.aivencloud.com)
- `DB_USER` - Database username (e.g., avnadmin)
- `DB_PASSWORD` - Database password (use a strong, unique password)
- `DB_DATABASE` - Database name (e.g., defaultdb)
- `DB_PORT` - Port number (default: 3306)

### Authentication
- `GOOGLE_CLIENT_ID` - From Google Cloud Console
- `GOOGLE_CLIENT_SECRET` - From Google Cloud Console (regenerate!)
- `SESSION_SECRET` - Long random string (generate with: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`)

### Environment
- `NODE_ENV` - Set to `production`

### Optional Security
- `ALLOWED_IP` - IP address to allow (optional)
- `ALLOWED_ISP_NAME` - ISP name to allow (optional)

## How to Deploy to Vercel

### 1. Connect Your Git Repository
```bash
# Push your code to GitHub (already done)
git push origin main
```

### 2. Create Vercel Project
- Go to [vercel.com](https://vercel.com)
- Click "Add New..." → "Project"
- Import your GitHub repository
- Select your project

### 3. Set Environment Variables
In Vercel Project Settings → "Environment Variables":
1. Add all required variables listed above
2. Set them for all environments (Production, Preview, Development)
3. Save

### 4. Deploy
- Vercel will automatically deploy when you push to main
- Or click "Deploy" in Vercel dashboard

### 5. Verify Deployment
Check the health endpoint:
```
https://your-vercel-url.vercel.app/api/health
```

Should return:
```json
{
  "status": "ok",
  "message": "Server is running"
}
```

## Troubleshooting

### "Internal Server Error"
1. Check Vercel logs: Project → Deployments → View Logs
2. Verify all environment variables are set
3. Check database connection: `DB_HOST`, `DB_USER`, `DB_PASSWORD`
4. Ensure Google OAuth credentials are correct

### "Cannot connect to database"
- Verify `DB_HOST` is correct
- Check if Aiven allows connections from Vercel IPs
- Test connection string locally first

### "Missing environment variables"
- Check Project Settings → Environment Variables
- Make sure variables are set for the right environment (Production)
- Redeploy after adding variables

### Database SSL Issues
If getting SSL errors:
1. Some cloud databases require SSL
2. Aiven usually provides SSL certificates
3. You might need to add `DB_SSL_CA` variable with certificate content

## Security Reminders

⚠️ **NEVER** commit `.env` to Git
✅ Always use `.env` for local development
✅ Use Vercel's environment variable UI for production
✅ Regenerate secrets after any potential exposure
✅ Keep Google OAuth credentials secure

## Monitoring

### View Logs
```bash
vercel logs [--follow]
```

### View Real-time Logs
In Vercel dashboard: Deployments → Functions → Logs

## Rolling Back

If deployment breaks:
1. Go to Vercel Deployments
2. Find previous working deployment
3. Click three dots → "Promote to Production"

## Additional Resources
- [Vercel Node.js Documentation](https://vercel.com/docs/frameworks/nodejs)
- [Environment Variables on Vercel](https://vercel.com/docs/projects/environment-variables)
