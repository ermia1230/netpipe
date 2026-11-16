# Quick Setup Guide

## What You Need to Do

### 1. Install Dependencies
```bash
cd "/Users/ermiaghaffari/Desktop/untitled folder"
npm install
```

### 2. Set Up Firebase

**Create a Firebase Project:**
1. Visit: https://console.firebase.google.com/
2. Click "Add Project"
3. Enter project name (e.g., "chat-call-app")
4. Click through the setup (you can disable Google Analytics if you want)

**Enable Authentication:**
1. In Firebase Console, click "Authentication" in the left sidebar
2. Click "Get Started"
3. Click "Email/Password" under Sign-in providers
4. Toggle "Enable" and click "Save"

**Enable Firestore:**
1. Click "Firestore Database" in the left sidebar
2. Click "Create database"
3. Start in "test mode" (for development)
4. Choose a location close to you
5. Click "Enable"

**Get Firebase Config:**
1. Click the gear icon ⚙️ next to "Project Overview"
2. Click "Project settings"
3. Scroll down to "Your apps"
4. Click the Web icon (</>)
5. Register app (give it a nickname like "chat-app")
6. Copy the `firebaseConfig` object

**Update Your Code:**
Open `config/firebase.js` and paste your config:
```javascript
export const firebaseConfig = {
  apiKey: "paste-your-api-key-here",
  authDomain: "your-project.firebaseapp.com",
  projectId: "your-project-id",
  storageBucket: "your-project.appspot.com",
  messagingSenderId: "123456789",
  appId: "1:123456789:web:abcdef"
};
```

### 3. Run the App

```bash
npx expo start
```

**Options:**
- Press `i` - Open iOS simulator (requires Xcode on Mac)
- Press `a` - Open Android emulator (requires Android Studio)
- Scan QR code with Expo Go app on your phone

### 4. Test the App

1. **Create Account**: Use any email format (doesn't need to be real for testing)
2. **Sign In**: Use the same credentials

### 5. Create a Test Chat

Since we don't have a user search yet, manually create a chat in Firebase:

1. Go to Firestore Database in Firebase Console
2. Click "Start collection"
3. Collection ID: `chats`
4. Add first document:
   - Document ID: (auto-generate)
   - Field: `participants` | Type: array | Value: [your-user-id-1, your-user-id-2]
   - Field: `participantNames` | Type: array | Value: [email1@test.com, email2@test.com]
   - Field: `lastMessage` | Type: string | Value: (empty)
   - Field: `lastMessageTime` | Type: timestamp | Value: (click to add timestamp)

**To get user IDs:**
- Create two accounts in your app
- Go to Firebase Console > Authentication
- Copy the "User UID" for each user

## Troubleshooting

**"Unable to resolve module"**
- Run: `npm install`
- Clear cache: `npx expo start -c`

**Firebase errors:**
- Double-check your config in `config/firebase.js`
- Make sure Authentication and Firestore are enabled in Firebase Console

**App crashes on startup:**
- Check that all npm packages installed successfully
- Try: `rm -rf node_modules && npm install`

## What's Included

✅ Login/Signup with email/password
✅ Real-time chat messaging
✅ Chat list view
✅ Call UI (placeholder)
✅ Firebase authentication
✅ Firestore database integration

## What's NOT Included (Future Features)

- User search/discovery
- Actual audio/video calling (requires WebRTC)
- Push notifications
- Profile pictures
- Group chats
- File/image sharing
- Read receipts
- Online status

Ready to build upon this foundation! 🚀
