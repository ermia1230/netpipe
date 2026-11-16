# 🚀 START HERE - Complete Setup Instructions

## ✅ What I Need You To Do

### Step 1: Install Node Modules (2 minutes)

Open Terminal and run:
```bash
cd "/Users/ermiaghaffari/Desktop/untitled folder"
npm install
```

Wait for installation to complete.

---

### Step 2: Set Up Firebase (5-10 minutes)

#### A. Create Firebase Project
1. Go to: **https://console.firebase.google.com/**
2. Click **"Add project"** or **"Create a project"**
3. Enter project name: `chat-call-app` (or any name you want)
4. Continue through setup (disable Analytics if you want - not needed for now)

#### B. Enable Email/Password Authentication
1. In your Firebase project, click **"Authentication"** in left sidebar
2. Click **"Get started"** button
3. Click **"Email/Password"** under Sign-in providers
4. **Toggle "Enable"** on
5. Click **"Save"**

#### C. Enable Firestore Database
1. Click **"Firestore Database"** in left sidebar
2. Click **"Create database"**
3. Select **"Start in test mode"**
4. Choose a location (pick closest to you)
5. Click **"Enable"**

#### D. Get Your Firebase Configuration
1. Click the **gear icon ⚙️** next to "Project Overview"
2. Click **"Project settings"**
3. Scroll to **"Your apps"** section
4. Click the **web icon** `</>`
5. Register app: enter nickname like `chat-app-web`
6. **Copy the `firebaseConfig` object** (looks like this):

```javascript
const firebaseConfig = {
  apiKey: "AIza...",
  authDomain: "your-project.firebaseapp.com",
  projectId: "your-project-123",
  storageBucket: "your-project.appspot.com",
  messagingSenderId: "123456",
  appId: "1:123:web:abc"
};
```

#### E. Update Your Code
1. Open file: **`config/firebase.js`**
2. Replace the placeholder values with YOUR config:

```javascript
export const firebaseConfig = {
  apiKey: "YOUR_ACTUAL_API_KEY_HERE",
  authDomain: "your-project-id.firebaseapp.com",
  projectId: "your-actual-project-id",
  storageBucket: "your-project-id.appspot.com",
  messagingSenderId: "your-actual-sender-id",
  appId: "your-actual-app-id"
};
```

**IMPORTANT:** Replace ALL the values with your actual Firebase config!

---

### Step 3: Run the App (1 minute)

In Terminal, run:
```bash
npx expo start
```

You'll see:
- QR code
- Options to open in simulator/emulator

**To test:**
- **iPhone:** Press `i` (requires Xcode on Mac)
- **Android:** Press `a` (requires Android Studio)
- **Phone:** Install "Expo Go" app, scan QR code

---

## 🎯 How to Use the App

### First Time:
1. **Create Account:** 
   - Enter any email (doesn't need to be real): `user1@test.com`
   - Enter password: `password123`
   - Click "Sign Up"

2. **Start a Chat:**
   - Click the **blue + button** at bottom right
   - Enter another email: `user2@test.com`
   - Click "Start Chat"
   - Send a message!

3. **Test with Second User:**
   - Sign out (icon in top right)
   - Create second account: `user2@test.com` / `password123`
   - You'll see the chat!

4. **Make a Call:**
   - Open a chat
   - Click the **phone icon** in top right
   - (Note: This is just UI for now - real calls need WebRTC)

---

## 📱 App Features

✅ **Working Now:**
- User authentication (sign up/sign in)
- Real-time chat messaging
- Multiple chats management
- Call UI (visual only)

🔨 **To Build Later:**
- Real audio/video calls (WebRTC)
- User search & discovery
- Profile pictures
- Push notifications
- Group chats
- Image/file sharing
- Read receipts
- Typing indicators

---

## ❓ Troubleshooting

**"Cannot find module" errors:**
```bash
npm install
npx expo start -c
```

**Firebase errors:**
- Check `config/firebase.js` has YOUR actual config
- Make sure Auth and Firestore are enabled in Firebase Console

**App won't load:**
```bash
rm -rf node_modules package-lock.json
npm install
npx expo start -c
```

**Expo Go connection issues:**
- Make sure phone and computer are on same WiFi
- Try scanning QR code again
- Check firewall settings

---

## 📂 Project Structure

```
├── App.js                      # Main app entry point
├── config/
│   ├── firebase.js            # 🔴 UPDATE THIS with your Firebase config
│   └── firebaseInit.js        # Firebase initialization
├── screens/
│   ├── LoginScreen.js         # Login/Signup UI
│   ├── ChatsListScreen.js     # All chats list
│   ├── NewChatScreen.js       # Start new chat
│   ├── ChatScreen.js          # Individual chat messages
│   └── CallScreen.js          # Call UI (placeholder)
├── utils/
│   └── chatUtils.js           # Helper functions
└── package.json               # Dependencies
```

---

## 🎨 Customization Ideas

1. **Change Colors:**
   - Find `#007AFF` in all files (iOS blue)
   - Replace with your brand color

2. **Add App Name:**
   - Update `app.json` → `"name": "YourAppName"`

3. **Better Icons:**
   - Add images to `assets/` folder
   - Update `app.json` paths

---

## 🚀 Next Steps After Basic Setup

1. **Test thoroughly** - Create multiple users, send messages
2. **Customize design** - Colors, fonts, layouts
3. **Add features** - Pick from the list above
4. **Deploy** - Build for App Store/Play Store

---

## 📞 Adding Real Calls (Advanced)

For actual calling, you'll need:
1. **WebRTC** library (expo-av or react-native-webrtc)
2. **Signaling server** (Firebase Realtime DB or custom)
3. **STUN/TURN servers** (Twilio, Agora, or free alternatives)

This is a bigger task - start simple and add later!

---

## ✨ You're All Set!

Once you:
1. ✅ Run `npm install`
2. ✅ Update `config/firebase.js`
3. ✅ Run `npx expo start`

You'll have a working chat app! 🎉

**Questions?** Check `SETUP.md` or `README.md` for more details.
