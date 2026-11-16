# Chat & Call App - React Native with Expo & Firebase

A simple chat and call app built with React Native, Expo, and Firebase.

## Features

- 🔐 User Authentication (Email/Password)
- 💬 Real-time Chat Messaging
- 📞 Call UI (placeholder for WebRTC integration)
- 🔥 Firebase Integration (Auth & Firestore)

## Setup Instructions

### Prerequisites

- Node.js installed on your computer
- Expo CLI installed (`npm install -g expo-cli`)
- A Firebase account

### Step 1: Install Dependencies

```bash
npm install
```

### Step 2: Firebase Setup

1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Create a new project (or use existing one)
3. Enable **Authentication**:
   - Go to Authentication > Sign-in method
   - Enable "Email/Password" provider
4. Enable **Firestore Database**:
   - Go to Firestore Database
   - Create database in "test mode" (or production mode with security rules)
5. Get your Firebase config:
   - Go to Project Settings > Your apps
   - Click "Web app" (</>) to register a web app
   - Copy the configuration object

### Step 3: Configure Firebase

Open `config/firebase.js` and replace the placeholder values with your actual Firebase configuration:

```javascript
export const firebaseConfig = {
  apiKey: "YOUR_API_KEY",
  authDomain: "YOUR_PROJECT_ID.firebaseapp.com",
  projectId: "YOUR_PROJECT_ID",
  storageBucket: "YOUR_PROJECT_ID.appspot.com",
  messagingSenderId: "YOUR_MESSAGING_SENDER_ID",
  appId: "YOUR_APP_ID"
};
```

### Step 4: Set Up Firestore Security Rules (Optional but Recommended)

In Firebase Console > Firestore Database > Rules, add:

```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /chats/{chatId} {
      allow read, write: if request.auth != null && 
        request.auth.uid in resource.data.participants;
      
      match /messages/{messageId} {
        allow read, write: if request.auth != null;
      }
    }
  }
}
```

### Step 5: Run the App

```bash
npx expo start
```

Then:
- Press `i` for iOS simulator
- Press `a` for Android emulator
- Scan QR code with Expo Go app on your phone

## How to Use

1. **Sign Up**: Create an account with email and password
2. **Create a Chat**: You'll need to manually create chat documents in Firestore for now
3. **Send Messages**: Open a chat and start messaging
4. **Make a Call**: Click the call icon in a chat (UI placeholder only)

## Creating a Test Chat Manually

To test the chat feature, create a document in Firestore:

1. Go to Firestore Database in Firebase Console
2. Create a collection called `chats`
3. Add a document with these fields:
   ```
   participants: [userId1, userId2]  // Array of user IDs
   participantNames: [email1, email2]  // Array of user emails
   lastMessage: ""
   lastMessageTime: [current timestamp]
   ```

## Project Structure

```
├── App.js                      # Main app with navigation
├── config/
│   ├── firebase.js             # Firebase configuration
│   └── firebaseInit.js         # Firebase initialization
├── screens/
│   ├── LoginScreen.js          # Login/Signup screen
│   ├── ChatsListScreen.js      # List of all chats
│   ├── ChatScreen.js           # Individual chat screen
│   └── CallScreen.js           # Call screen (UI only)
├── package.json
└── app.json
```

## Next Steps to Build Upon

1. **Add User Search**: Create a screen to search and start chats with users
2. **Real Calls**: Integrate WebRTC for actual audio/video calling
3. **Push Notifications**: Add Firebase Cloud Messaging for notifications
4. **User Profiles**: Add profile pictures and user information
5. **Group Chats**: Extend to support multiple participants
6. **Media Sharing**: Add image/video sharing in chats
7. **Read Receipts**: Show when messages are read
8. **Typing Indicators**: Show when someone is typing

## Technologies Used

- React Native
- Expo
- Firebase (Authentication & Firestore)
- React Navigation

## Notes

- The call functionality is currently a UI placeholder
- For production, implement proper Firestore security rules
- Consider adding error handling and loading states
- Add form validation for better UX
