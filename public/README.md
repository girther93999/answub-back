# Artic Auth - Frontend

## Hosting Instructions

### Option 1: Host on Render (with Backend)
Frontend is served automatically by the backend server.
Just deploy the backend and access:
`https://your-app.onrender.com`

### Option 2: Host Separately (Static Site)
1. Push this `frontend/` folder to GitHub
2. Deploy to:
   - Netlify
   - Vercel
   - GitHub Pages
   - Any static host

3. Update API URL in `auth.js` and `dashboard.js`:
   ```javascript
   const API = 'https://your-backend.onrender.com/api';
   ```

## Files:
- `index.html` - Login/signup page
- `dashboard.html` - User dashboard
- `auth.js` - Login logic
- `dashboard.js` - Dashboard logic
- `style.css` - Styles

