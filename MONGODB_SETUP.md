# MongoDB Setup for Persistent Storage

## Why MongoDB?
Your accounts and keys will persist even when the server restarts! No more lost data.

## Quick Setup (5 minutes):

1. **Create free MongoDB Atlas account:**
   - Go to https://www.mongodb.com/cloud/atlas/register
   - Sign up (free tier available)

2. **Create a cluster:**
   - Click "Build a Database"
   - Choose FREE tier (M0)
   - Select a cloud provider/region
   - Click "Create"

3. **Create database user:**
   - Click "Database Access" → "Add New Database User"
   - Username: `astreon` (or any username)
   - Password: Generate a secure password (save it!)
   - Database User Privileges: "Read and write to any database"
   - Click "Add User"

4. **Whitelist your IP:**
   - Click "Network Access" → "Add IP Address"
   - Click "Allow Access from Anywhere" (0.0.0.0/0)
   - Click "Confirm"

5. **Get connection string:**
   - Click "Database" → "Connect" → "Connect your application"
   - Copy the connection string
   - Replace `<password>` with your database user password
   - Replace `<dbname>` with `astreon` (or any name)

6. **Add to Render.com:**
   - Go to your Render dashboard
   - Select your service
   - Go to "Environment" tab
   - Add new environment variable:
     - Key: `MONGODB_URI`
     - Value: Your connection string (from step 5)
   - Click "Save Changes"
   - Redeploy your service

## Example Connection String Format:
```
mongodb+srv://USERNAME:PASSWORD@cluster0.xxxxx.mongodb.net/DATABASE_NAME?retryWrites=true&w=majority
```

**Important:** Replace:
- `USERNAME` with your database username
- `PASSWORD` with your database password  
- `cluster0.xxxxx` with your actual cluster address
- `DATABASE_NAME` with your database name (e.g., `astreon`)

## That's it!
Once you set the `MONGODB_URI` environment variable, all your accounts and keys will be saved to MongoDB and will persist forever, even if the server restarts!

## Without MongoDB:
The system will still work using JSON files, but data may be lost on server restart (Render.com clears filesystem on restart).

