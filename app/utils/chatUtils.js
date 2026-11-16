import { collection, addDoc, query, where, getDocs } from 'firebase/firestore';
import { db } from '../config/firebaseInit';

/**
 * Create or get existing chat between two users
 * @param {string} currentUserId - Current user's ID
 * @param {string} otherUserId - Other user's ID
 * @param {string} currentUserEmail - Current user's email
 * @param {string} otherUserEmail - Other user's email
 * @returns {Promise<string>} - Chat ID
 */
export const createOrGetChat = async (
  currentUserId,
  otherUserId,
  currentUserEmail,
  otherUserEmail
) => {
  try {
    // Check if chat already exists
    const chatsRef = collection(db, 'chats');
    const q = query(
      chatsRef,
      where('participants', 'array-contains', currentUserId)
    );
    
    const snapshot = await getDocs(q);
    const existingChat = snapshot.docs.find((doc) => {
      const data = doc.data();
      return data.participants.includes(otherUserId);
    });

    if (existingChat) {
      return existingChat.id;
    }

    // Create new chat
    const newChat = await addDoc(chatsRef, {
      participants: [currentUserId, otherUserId],
      participantNames: [currentUserEmail, otherUserEmail],
      lastMessage: '',
      lastMessageTime: new Date(),
    });

    return newChat.id;
  } catch (error) {
    console.error('Error creating/getting chat:', error);
    throw error;
  }
};

/**
 * Get all users (for user search functionality)
 * Note: In production, you'd want to use Cloud Functions or a different approach
 * as Firestore doesn't have a built-in users collection
 */
export const getAllUsers = async (currentUserId) => {
  // This is a placeholder - you'll need to implement user listing
  // One approach: maintain a 'users' collection when users sign up
  // For now, users need to know each other's IDs to chat
  return [];
};
