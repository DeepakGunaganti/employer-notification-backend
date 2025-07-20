// employer-notification-backend/server.js

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const handlebars = require('handlebars');
const fs = require('fs');
const path = require('path');
const http = require('http');
const { Server } = require('socket.io');
const admin = require('firebase-admin');

const app = express();
const PORT = process.env.PORT || 5000;

const allowedOrigin = process.env.NODE_ENV === 'production'
  ? process.env.FRONTEND_URL
  : 'http://localhost:3000';

const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: allowedOrigin,
    methods: ["GET", "POST", "PUT", "DELETE"]
  }
});

// --- Firebase Admin SDK Initialization (MODIFIED TO READ INDIVIDUAL ENV VARS) ---
try {
  let serviceAccountConfig;

  if (process.env.NODE_ENV === 'production') {
    // In production, reconstruct service account from individual environment variables
    // IMPORTANT: The private_key needs its newline characters restored from the escaped string
    const privateKey = process.env.FIREBASE_PRIVATE_KEY ? process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n') : undefined;

    serviceAccountConfig = {
      type: process.env.FIREBASE_TYPE,
      project_id: process.env.FIREBASE_PROJECT_ID_ADMIN, // Using a distinct name for clarity
      private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
      private_key: privateKey, // Use the reconstructed private key
      client_email: process.env.FIREBASE_CLIENT_EMAIL,
      client_id: process.env.FIREBASE_CLIENT_ID,
      auth_uri: process.env.FIREBASE_AUTH_URI,
      token_uri: process.env.FIREBASE_TOKEN_URI,
      auth_provider_x509_cert_url: process.env.FIREBASE_AUTH_PROVIDER_X509_CERT_URL,
      client_x509_cert_url: process.env.FIREBASE_CLIENT_X509_CERT_URL
    };
    // Basic check to ensure critical fields are present
    if (!serviceAccountConfig.project_id || !serviceAccountConfig.private_key || !serviceAccountConfig.client_email) {
      throw new Error("Missing one or more critical Firebase Admin environment variables for production.");
    }

  } else {
    // For local development, load from file as before
    serviceAccountConfig = require('./firebase-admin-key.json');
  }

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccountConfig)
  });
  console.log('Firebase Admin SDK initialized.');
} catch (error) {
  console.error('CRITICAL ERROR: Firebase Admin SDK initialization failed. Details:', error);
  console.error('Please ensure firebase-admin-key.json is present/valid locally, or ALL individual FIREBASE_ env vars are set correctly in production.');
  process.exit(1); // Exit if critical service fails to initialize
}


io.on('connection', (socket) => {
  console.log(`User connected: ${socket.id}`);

  socket.on('registerUser', (userId) => {
    socket.join(userId);
    console.log(`Socket ${socket.id} joined room for user ${userId}`);
  });

  socket.on('disconnect', () => {
    console.log(`User disconnected: ${socket.id}`);
  });
});

app.use(cors({
  origin: allowedOrigin,
  methods: ["GET", "POST", "PUT", "DELETE"]
}));
app.use(express.json());

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected successfully!'))
  .catch(err => console.error('MongoDB connection error:', err));

const notificationSchema = new mongoose.Schema({
  userId: { type: String, required: true, index: true },
  type: {
    type: String,
    enum: ["application", "interview", "feedback", "job_post_status", "suspicious_activity"],
    required: true
  },
  title: { type: String, required: true },
  message: { type: String, required: true },
  isRead: { type: Boolean, default: false },
  link: { type: String, required: true },
  createdAt: { type: Date, default: Date.now, index: true },
  priority: {
    type: String,
    enum: ["high", "medium", "low"],
    default: "medium"
  },
  priorityReason: { type: String },
  suggestedActions: { type: [String], default: [] },
});

const Notification = mongoose.model('Notification', notificationSchema);

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  secure: process.env.SMTP_SECURE === 'true',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

transporter.verify(function (error, success) {
  if (error) {
    console.error("Nodemailer transporter verification failed:", error);
  } else {
    console.log("Nodemailer transporter is ready to send messages");
  }
});

const compileTemplate = async (templateName, data) => {
  try {
    const filePath = path.join(__dirname, 'emailTemplates', `${templateName}.hbs`);
    const source = await fs.promises.readFile(filePath, 'utf8');
    const template = handlebars.compile(source);
    return template(data);
  } catch (error) {
    console.error(`Error compiling email template ${templateName}:`, error);
    throw new Error(`Could not compile email template: ${templateName}`);
  }
};

const sendNotificationEmail = async ({ to, subject, templateName, templateData }) => {
  try {
    const htmlBody = await compileTemplate(templateName, { ...templateData, currentYear: new Date().getFullYear() });

    const mailOptions = {
      from: process.env.EMAIL_FROM || 'no-reply@yourdomain.com',
      to,
      subject,
      html: htmlBody,
    };
    await transporter.sendMail(mailOptions);
    console.log(`Email sent successfully to ${to} with subject: ${subject}`);
  } catch (error) {
    console.error(`Error sending email to ${to}:`, error);
  }
};

const createNotificationLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message:
    "Too many notification creation requests from this IP, please try again after 15 minutes",
  standardHeaders: true,
  legacyHeaders: false,
});

const authenticateFirebaseToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Unauthorized: No Firebase ID token provided.' });
  }

  const idToken = authHeader.split('Bearer ')[1];

  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    req.user = { id: decodedToken.uid, email: decodedToken.email };
    next();
  } catch (error) {
    console.error('Error verifying Firebase ID token:', error);
    return res.status(401).json({ message: 'Unauthorized: Invalid or expired Firebase ID token.' });
  }
};

const determineNotificationPriority = async (type, title, message) => {
  const prompt = `Analyze the following employer notification and determine its priority (high, medium, or low) based on its urgency and importance for an employer. Provide a brief reason for your decision.

Notification Type: ${type}
Title: ${title}
Message: ${message}

Output your response as a JSON object with two keys: "priority" (string: "high", "medium", or "low") and "reason" (string).`;

  let chatHistory = [];
  chatHistory.push({ role: "user", parts: [{ text: prompt }] });

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
      console.warn('GEMINI_API_KEY is not set in .env. LLM priority will default to medium.');
      return { priority: 'medium', reason: 'API Key not configured.' };
  }

  const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;

  const payload = {
    contents: chatHistory,
    generationConfig: {
      responseMimeType: "application/json",
      responseSchema: {
        type: "OBJECT",
        properties: {
          priority: {
            type: "STRING",
            enum: ["high", "medium", "low"]
          },
          reason: {
            type: "STRING"
          }
        },
        required: ["priority", "reason"]
      }
    }
  };

  try {
    const response = await fetch(apiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('Gemini API error response:', errorText);
      throw new Error(`Gemini API request failed with status ${response.status}: ${errorText}`);
    }

    const result = await response.json();
    if (result.candidates && result.candidates.length > 0 &&
        result.candidates[0].content && result.candidates[0].content.parts &&
        result.candidates[0].content.parts.length > 0) {
      const jsonString = result.candidates[0].content.parts[0].text;
      const parsedJson = JSON.parse(jsonString);

      if (parsedJson.priority && ['high', 'medium', 'low'].includes(parsedJson.priority) && parsedJson.reason) {
        return {
          priority: parsedJson.priority,
          reason: parsedJson.reason
        };
      } else {
        console.warn('Gemini returned unexpected JSON structure for priority:', parsedJson);
        return { priority: 'medium', reason: 'LLM returned invalid format for priority. Defaulting to medium.' };
      }
    } else {
      console.warn('Gemini response missing candidates or content for priority:', result);
      return { priority: 'medium', reason: 'LLM response structure unexpected for priority. Defaulting to medium.' };
    }
  } catch (error) {
    console.error('Error calling Gemini API for priority:', error);
    return { priority: 'medium', reason: `Failed to get LLM priority: ${error.message}. Defaulting to medium.` };
  }
};

const detectSuspiciousActivity = async (type, title, message) => {
  if (!['application', 'interview'].includes(type)) {
    return { isSuspicious: false, reason: null };
  }

  const prompt = `Analyze the following notification for any suspicious patterns or red flags that an employer should be aware of. Focus on the text provided.
  Consider these examples of suspicious activity:
  -   Unusual or generic application message (e.g., "I am interested in any job")
  -   Excessive use of buzzwords without substance
  -   Requests for personal information or payment
  -   Inconsistent dates or information in an interview reschedule/decline
  -   Messages that seem automated or phishing-like
  -   Very short or empty messages for critical events like applications or feedback.

Notification Type: ${type}
Title: ${title}
Message: ${message}

Is this activity suspicious? Provide your response as a JSON object with two keys: "isSuspicious" (boolean) and "reason" (string, if suspicious, explain why).`;

  let chatHistory = [];
  chatHistory.push({ role: "user", parts: [{ text: prompt }] });

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
      console.warn('GEMINI_API_KEY is not set in .env. Skipping anomaly detection.');
      return { isSuspicious: false, reason: 'API Key not configured for anomaly detection.' };
  }

  const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;

  const payload = {
    contents: chatHistory,
    generationConfig: {
      responseMimeType: "application/json",
      responseSchema: {
        type: "OBJECT",
        properties: {
          isSuspicious: { "type": "BOOLEAN" },
          reason: { "type": "STRING" }
        },
        required: ["isSuspicious", "reason"]
      }
    }
  };

  try {
    const response = await fetch(apiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('Gemini API error response for anomaly detection:', errorText);
      return { isSuspicious: false, reason: `LLM API failed: ${errorText}` };
    }

    const result = await response.json();
    if (result.candidates && result.candidates.length > 0 &&
        result.candidates[0].content && result.candidates[0].content.parts &&
        result.candidates[0].content.parts.length > 0) {
      const jsonString = result.candidates[0].content.parts[0].text;
      const parsedJson = JSON.parse(jsonString);

      if (typeof parsedJson.isSuspicious === 'boolean' && parsedJson.reason !== undefined) {
        return {
          isSuspicious: parsedJson.isSuspicious,
          reason: parsedJson.reason
        };
      } else {
        console.warn('Gemini returned unexpected JSON structure for anomaly detection:', parsedJson);
        return { isSuspicious: false, reason: 'LLM returned invalid format for anomaly detection.' };
      }
    } else {
      console.warn('Gemini response missing candidates or content for anomaly detection:', result);
      return { isSuspicious: false, reason: 'LLM response structure unexpected for anomaly detection.' };
    }
  } catch (error) {
    console.error('Error calling Gemini API for anomaly detection:', error);
    return { isSuspicious: false, reason: `Failed to get LLM anomaly detection: ${error.message}` };
  }
};

const suggestActions = async (type, title, message) => {
  const prompt = `Based on the following employer notification, suggest 1 to 3 concise, actionable next steps an employer might take. Focus on practical actions.

Notification Type: ${type}
Title: ${title}
Message: ${message}

Output your response as a JSON array of strings, where each string is a suggested action.`;

  let chatHistory = [];
  chatHistory.push({ role: "user", parts: [{ text: prompt }] });

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
      console.warn('GEMINI_API_KEY is not set in .env. Skipping action suggestions.');
      return [];
  }

  const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;

  const payload = {
    contents: chatHistory,
    generationConfig: {
      responseMimeType: "application/json",
      responseSchema: {
        type: "ARRAY",
        items: { "type": "STRING" }
      }
    }
  };

  try {
    const response = await fetch(apiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('Gemini API error response for action suggestions:', errorText);
      return [];
    }

    const result = await response.json();
    if (result.candidates && result.candidates.length > 0 &&
        result.candidates[0].content && result.candidates[0].content.parts &&
        result.candidates[0].content.parts.length > 0) {
      const jsonString = result.candidates[0].content.parts[0].text;
      const parsedJson = JSON.parse(jsonString);

      if (Array.isArray(parsedJson) && parsedJson.every(item => typeof item === 'string')) {
        return parsedJson;
      } else {
        console.warn('Gemini returned unexpected JSON structure for action suggestions:', parsedJson);
        return [];
      }
    } else {
      console.warn('Gemini response missing candidates or content for action suggestions:', result);
      return [];
    }
  } catch (error) {
    console.error('Error calling Gemini API for action suggestions:', error);
    return [];
  }
};


// --- API Endpoints ---

// 1. POST /api/notification/send - Trigger from backend events
app.post('/api/notification/send', createNotificationLimiter, authenticateFirebaseToken, async (req, res) => {
  try {
    const authenticatedUserId = req.user.id;
    const { type, title, message, link, emailRecipient, emailTemplateName, emailTemplateData } = req.body;

    if (!type || !title || !message || !link) {
      return res.status(400).json({ message: 'Missing required notification fields.' });
    }

    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
    const existingNotification = await Notification.findOne({
      userId: authenticatedUserId,
      type,
      title,
      createdAt: { $gte: fiveMinutesAgo }
    });

    if (existingNotification) {
      console.log('Duplicate notification prevented:', { userId: authenticatedUserId, type, title });
      return res.status(409).json({ message: 'Duplicate notification detected. Not sending.' });
    }

    const { priority, reason: priorityReason } = await determineNotificationPriority(type, title, message);
    const suggestedActions = await suggestActions(type, title, message);

    const newNotification = new Notification({
      userId: authenticatedUserId,
      type,
      title,
      message,
      isRead: false,
      link,
      createdAt: new Date(),
      priority: priority,
      priorityReason: priorityReason,
      suggestedActions: suggestedActions,
    });

    await newNotification.save();
    console.log('In-app notification saved:', newNotification);

    io.to(authenticatedUserId).emit('newNotification', newNotification);
    console.log(`Emitted 'newNotification' to user ${authenticatedUserId}`);

    const { isSuspicious, reason: suspiciousReason } = await detectSuspiciousActivity(type, title, message);

    if (isSuspicious) {
      console.warn(`Suspicious activity detected for user ${authenticatedUserId}: ${suspiciousReason}`);
      const suspiciousNotification = new Notification({
        userId: authenticatedUserId,
        type: 'suspicious_activity',
        title: 'Suspicious Activity Detected!',
        message: `An unusual pattern was detected in a recent event: ${suspiciousReason}. Please investigate.`,
        isRead: false,
        link: newNotification.link,
        createdAt: new Date(),
        priority: 'high',
        priorityReason: suspiciousReason
      });
      await suspiciousNotification.save();
      io.to(authenticatedUserId).emit('newNotification', suspiciousNotification);
      console.log(`Emitted 'suspicious_activity' notification to user ${authenticatedUserId}`);
    }


    if (emailRecipient && emailTemplateName && emailTemplateData) {
      await sendNotificationEmail({
        to: emailRecipient,
        subject: title,
        templateName: emailTemplateName,
        templateData: emailTemplateData
      });
    }

    res.status(201).json({ message: 'Notification sent and saved successfully', notification: newNotification });
  } catch (error) {
    console.error('Error sending notification:', error);
    res.status(500).json({ message: 'Internal server error', error: error.message });
  }
});

// 2. GET /api/notification/:userId - Fetch notifications for a user
app.get('/api/notification/:userId', authenticateFirebaseToken, async (req, res) => {
  try {
    const requestedUserId = req.params.userId;
    const authenticatedUserId = req.user.id;

    if (requestedUserId !== authenticatedUserId) {
        return res.status(403).json({ message: 'Forbidden: You can only view your own notifications.' });
    }

    const notifications = await Notification.find({ userId: authenticatedUserId })
      .sort({ createdAt: -1 })
      .lean();

    res.status(200).json(notifications);
  } catch (error) {
    console.error('Error fetching notifications:', error);
    res.status(500).json({ message: 'Internal server error', error: error.message });
  }
});

// 3. POST /api/notification/read - Mark specific/all as read
app.post('/api/notification/read', authenticateFirebaseToken, async (req, res) => {
  try {
    const { notificationIds, isRead } = req.body;
    const authenticatedUserId = req.user.id;

    if (notificationIds === undefined && req.body.markAll === true) {
      await Notification.updateMany({ userId: authenticatedUserId }, { $set: { isRead: isRead } });
      io.to(authenticatedUserId).emit('notificationsUpdated', { type: 'markAll', userId: authenticatedUserId, isRead: isRead });
      console.log(`Emitted 'notificationsUpdated' (markAll) to user ${authenticatedUserId}`);
      res.status(200).json({ message: `All notifications for user ${authenticatedUserId} marked as ${isRead ? 'read' : 'unread'}.` });
    } else if (notificationIds && Array.isArray(notificationIds) && notificationIds.length > 0) {
      const notificationsToUpdate = await Notification.find({ _id: { $in: notificationIds } });

      const unauthorizedNotifications = notificationsToUpdate.filter(
        notif => notif.userId.toString() !== authenticatedUserId
      );

      if (unauthorizedNotifications.length > 0) {
        return res.status(403).json({ message: 'Forbidden: You do not own all notifications you are trying to modify.' });
      }

      await Notification.updateMany(
        { _id: { $in: notificationIds } },
        { $set: { isRead: isRead } }
      );
      io.to(authenticatedUserId).emit('notificationsUpdated', { type: 'markSpecific', notificationIds: notificationIds, isRead: isRead, userId: authenticatedUserId });
      console.log(`Emitted 'notificationsUpdated' (markSpecific) to user ${authenticatedUserId}`);
      res.status(200).json({ message: `Notifications marked as ${isRead ? 'read' : 'unread'}.` });
    } else {
      return res.status(400).json({ message: 'Invalid request. Provide notificationIds or markAll with isRead.' });
    }
  } catch (error) {
    console.error('Error marking notifications:', error);
    res.status(500).json({ message: 'Internal server error', error: error.message });
  }
});

// 4. DELETE /api/notification/:id - Delete a notification
app.delete('/api/notification/:id', authenticateFirebaseToken, async (req, res) => {
  try {
    const { id } = req.params;
    const authenticatedUserId = req.user.id;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ message: 'Invalid notification ID format.' });
    }

    const notificationToDelete = await Notification.findById(id);
    if (!notificationToDelete) {
      return res.status(404).json({ message: 'Notification not found.' });
    }
    if (notificationToDelete.userId.toString() !== authenticatedUserId) {
      return res.status(403).json({ message: 'Forbidden: You do not own this notification.' });
    }

    await Notification.findByIdAndDelete(id);
    io.to(authenticatedUserId).emit('notificationDeleted', { id: id, userId: authenticatedUserId });
    console.log(`Emitted 'notificationDeleted' for ID ${id} to user ${authenticatedUserId}`);

    res.status(200).json({ message: 'Notification deleted successfully.' });
  } catch (error) {
    console.error('Error deleting notification:', error);
    res.status(500).json({ message: 'Internal server error', error: error.message });
  }
});


// Basic Route for testing (keep this)
app.get('/', (req, res) => {
  res.send('Notification System Backend is running!');
});

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
