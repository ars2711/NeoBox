# OAuth Integration Setup Guide

## Overview

NeoBox now supports OAuth 2.0 authentication with Google, Microsoft, and Apple. Users can sign up and log in using their existing accounts from these providers.

## Implementation Status

### ✅ Completed

- **UI Integration**: Added OAuth buttons to login and registration pages
- **Backend Routes**: Implemented OAuth callback handlers for all three providers
- **Database Models**: Added OAuth ID columns to User model and LinkedAuthProvider table
- **OAuth Configuration**: Set up Flask-Dance (Google) and Authlib (Microsoft, Apple)
- **Dependencies**: Updated requirements.txt with necessary libraries

### 🔐 OAuth Providers Configured

#### 1. **Google OAuth 2.0**

- **Library**: Flask-Dance
- **Route**: `/login` (flask-dance handles the blueprint)
- **Callback**: `/google/authorized` (automatic via flask-dance)
- **User Handler**: `/login/google`
- **Scope**: openid, profile, email

#### 2. **Microsoft OAuth 2.0**

- **Library**: Authlib
- **Route**: `/login/microsoft`
- **Callback**: `/authorize/microsoft`
- **User Handler**: `authorize_microsoft()`
- **Scope**: openid, email, profile, User.Read

#### 3. **Apple OAuth 2.0 (Sign in with Apple)**

- **Library**: Authlib
- **Route**: `/login/apple`
- **Callback**: `/authorize/apple`
- **User Handler**: `authorize_apple()`
- **Scope**: openid, email, name
- **Special Note**: Decodes JWT ID token to get user info

## What You Need to Do

### Step 1: Set Up OAuth Credentials

#### **Google OAuth**

1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Create a new project or select existing one
3. Enable Google+ API
4. Create OAuth 2.0 credentials (Web application)
5. Add authorized redirect URIs:
   - `http://localhost:5000/login/google/authorized` (local dev)
   - `https://yourdomain.com/login/google/authorized` (production)
6. Copy **Client ID** and **Client Secret**

#### **Microsoft OAuth**

1. Go to [Azure Portal](https://portal.azure.com)
2. Navigate to Azure Active Directory → App registrations
3. Create new application registration
4. Add redirect URIs:
   - `http://localhost:5000/authorize/microsoft` (local dev)
   - `https://yourdomain.com/authorize/microsoft` (production)
5. Create a client secret
6. Grant API permissions: `User.Read`, `email`, `profile`
7. Copy **Application ID (Client ID)** and **Client Secret**

#### **Apple OAuth**

1. Go to [Apple Developer Account](https://developer.apple.com/account)
2. Register a new App ID with "Sign in with Apple" capability
3. Create a Service ID for Sign in with Apple
4. Register redirect URIs:
   - `https://localhost:5000/authorize/apple` (local dev - requires HTTPS)
   - `https://yourdomain.com/authorize/apple` (production)
5. Create a private key for authentication
6. Copy **Service ID**, **Team ID**, and **Key ID**
7. Create JWT for Apple authentication (see: [Apple OAuth Implementation](https://developer.apple.com/documentation/sign_in_with_apple))

### Step 2: Update Environment Variables

Create or update your `.env` file with the following:

```env
# Google OAuth
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret

# Microsoft OAuth
MICROSOFT_CLIENT_ID=your_microsoft_client_id
MICROSOFT_CLIENT_SECRET=your_microsoft_client_secret

# Apple OAuth
APPLE_CLIENT_ID=your_apple_service_id
APPLE_CLIENT_SECRET=your_apple_private_key_or_jwt
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

Key packages installed:

- `Flask-Dance>=6.2` - Google OAuth
- `authlib>=1.2` - Microsoft and Apple OAuth
- `python-jose>=3.3` - JWT decoding for Apple

### Step 4: Database Migration

The following models are involved:

- `User` table: Added `google_id`, `microsoft_id`, `apple_id` columns
- `LinkedAuthProvider` table: Stores mapping of external OAuth IDs to users

If using existing database, you may need to add these columns:

```sql
ALTER TABLE users ADD COLUMN google_id VARCHAR(128) UNIQUE;
ALTER TABLE users ADD COLUMN microsoft_id VARCHAR(128) UNIQUE;
ALTER TABLE users ADD COLUMN apple_id VARCHAR(128) UNIQUE;
```

### Step 5: Test the Integration

1. **Local Development**:
   - For Google & Microsoft: Use `http://localhost:5000`
   - For Apple: Use HTTPS (can use ngrok or similar for testing)

2. **Test Flows**:
   - Click OAuth buttons on login/register page
   - Verify user is created/logged in
   - Check `Users` table for OAuth IDs
   - Check `linked_auth_providers` table for linked accounts

## Features Implemented

### ✨ Account Features

1. **New User Registration via OAuth**
   - User clicks OAuth button
   - Redirected to provider
   - Auto-creates account with provider email
   - Username generated from email (auto-incremented if duplicate)
   - User is immediately logged in

2. **Existing User Login via OAuth**
   - User clicks OAuth button
   - If account exists with same email → logged in
   - If OAuth ID matches → logged in
   - Sets OAuth ID if not already set

3. **Account Linking** (for logged-in users)
   - User can link additional OAuth providers
   - Prevents linking same provider twice
   - Prevents linking if other user already has that OAuth ID
   - Creates entry in `LinkedAuthProvider` table

4. **Error Handling**
   - Graceful failures with user-friendly messages
   - Fallback options (traditional login page)
   - Session management
   - Email validation

## UI/UX Components

### Login Page (`templates/login.html`)

- OAuth buttons integrated below password field
- Shows Google, Microsoft, Apple options
- Labels: "Log in with [Provider]"
- Styling: Consistent with existing design

### Register Page (`templates/register.html`)

- OAuth buttons below sign-up form
- Three-button grid layout
- Additional text: "You can add more ways to sign in later"
- Same styling as login page

## Security Considerations

1. **HTTPS Required**
   - OAuth requires HTTPS in production
   - Apple specifically requires HTTPS even for local testing

2. **Token Handling**
   - Tokens are not stored (stateless after user lookup)
   - ID tokens are verified via provider
   - User info fetched fresh from provider API

3. **Password Generation**
   - OAuth accounts get random hash (dummy password)
   - User can set real password later
   - Password not required for OAuth users

4. **Email Validation**
   - All OAuth providers must return email
   - Email is unique constraint in database
   - Prevents duplicate accounts

## File Structure

```
NeoBox/
├── application.py              # Main app with OAuth routes
├── templates/
│   ├── login.html             # Login page with OAuth buttons
│   ├── register.html          # Register page with OAuth buttons
│   └── layout.html            # Base template
├── requirements.txt           # Dependencies (updated)
├── .env                       # OAuth credentials (CREATE THIS)
└── OAUTH_SETUP.md            # This file
```

## Troubleshooting

### OAuth button not working

- Check environment variables are set
- Verify redirect URIs match exactly in provider dashboard
- Check browser console for errors
- Verify provider credentials

### "Authorization failed" error

- Check client ID and secret are correct
- Verify redirect URIs match
- Ensure provider API is enabled
- Check provider-specific requirements (e.g., Apple email scope)

### User creation fails

- Check database migrations
- Verify email is not duplicate
- Check console logs for specific error

### Apple OAuth not working locally

- Requires HTTPS (use ngrok: `ngrok http 5000`)
- Update redirect URI in Apple dev account
- Use HTTPS URL in browser

## Next Steps

1. **Create OAuth app credentials** (see Step 1 above)
2. **Set environment variables** (see Step 2 above)
3. **Install dependencies**: `pip install -r requirements.txt`
4. **Test locally**: Try OAuth login/register flows
5. **Deploy to production**: Update redirect URIs in provider dashboards
6. **Monitor**: Check logs for OAuth errors

## Support

For provider-specific documentation:

- [Google OAuth 2.0](https://developers.google.com/identity/protocols/oauth2/web-server)
- [Microsoft Identity Platform](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow)
- [Sign in with Apple](https://developer.apple.com/documentation/sign_in_with_apple)

---

**Last Updated**: 2024
**Status**: Ready for OAuth Credentials Setup
