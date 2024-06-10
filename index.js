// ** Privus - Secure Your Links ** //
const express = require('express');
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const axios = require('axios');
require('dotenv').config();

const app = express();
const prisma = new PrismaClient();

app.use(express.json());

// Middleware for authentication
function authenticateToken(req, res, next) {
      const token = req.headers['authorization'];
      if (!token) return res.sendStatus(401);

      jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
            if (err) return res.sendStatus(403);
            req.user = user;
            next();
      });
}

// Validate URL
function isValidUrl(urlString) {
      try {
            new URL(urlString);
            return true;
      } catch (err) {
            return false;
      }
}

// Hash with bcrypt and truncate to desired length
async function hashUrl(url) {
      const salt = await bcrypt.genSalt(10);
      const hash = await bcrypt.hash(url, salt);
      return hash.substring(0, 57); // Adjust length to 57 characters
}

// User registration
app.post('/register', async (req, res) => {
      const { email, password } = req.body;

      if (!email || !password) {
            return res.status(400).json({ error: "Email and password are required" });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      try {
            const user = await prisma.user.create({
                  data: {
                        email,
                        password: hashedPassword
                  }
            });
            res.status(201).json({ message: "User registered successfully" });
      } catch (error) {
            res.status(500).json({ error: "Internal Server Error" });
      }
});

// User login
app.post('/login', async (req, res) => {
      const { email, password } = req.body;

      if (!email || !password) {
            return res.status(400).json({ error: "Email and password are required" });
      }

      const user = await prisma.user.findUnique({ where: { email } });
      if (!user) return res.status(400).json({ error: "Invalid email or password" });

      const validPassword = await bcrypt.compare(password, user.password);
      if (!validPassword) return res.status(400).json({ error: "Invalid email or password" });

      const accessToken = jwt.sign({ id: user.id, email: user.email }, process.env.ACCESS_TOKEN_SECRET);
      res.json({ accessToken });
});

app.post('/create-key', authenticateToken, async (req, res) => {
      const { value } = req.body;
      if (!value) {
            return res.status(400).json({ error: "Key value is required" });
      }

      try {
            const key = await prisma.key.create({
                  data: {
                        value,
                        userId: req.user.id
                  }
            });
            res.status(201).json({ message: "Key created successfully", key });
      } catch (error) {
            res.status(500).json({ error: "Internal Server Error" });
      }
});



// Create hashed URL
app.post('/hash', authenticateToken, async (req, res) => {
      const { url, key } = req.body;

      if (!url || !isValidUrl(url)) {
            return res.status(400).json({ error: "Valid URL is required" });
      }

      let keyId = null;
      let isPublic = true;

      if (key) {
            const userKey = await prisma.key.findUnique({ where: { value: key } });

            if (!userKey) {
                  return res.status(400).json({ error: "Invalid key" });
            }

            if (userKey.userId !== req.user.id) {
                  return res.status(403).json({ error: "Access denied" });
            }

            keyId = userKey.id;
            isPublic = false;
      }

      try {
            const hash = await hashUrl(url);
            const savedUrl = await prisma.url.create({
                  data: {
                        url,
                        hash,
                        userId: req.user.id,
                        keyId,
                        isPublic
                  }
            });

            res.json({ id: savedUrl.id, hash, privateUrl: `http://localhost:${PORT}/url/${encodeURIComponent(hash)}` });
      } catch (error) {
            res.status(500).json({ error: "Internal Server Error" });
      }
});

// Retrieve content from original URL by hash
app.get('/url/:hash', authenticateToken, async (req, res) => {
      const { hash } = req.params;

      try {
            const urlEntry = await prisma.url.findFirst({ where: { hash: decodeURIComponent(hash) } });
            if (!urlEntry || (!urlEntry.isPublic && req.user?.id !== urlEntry.userId)) {
                  return res.status(404).send("Private link not found or access denied");
            }

            try {
                  const response = await axios.get(urlEntry.url);

                  // Set the same headers and status as the original response
                  res.set(response.headers);
                  res.status(response.status);

                  // Send the content
                  res.send(response.data);
            } catch (axiosError) {
                  res.status(axiosError.response?.status || 500).send("Error fetching content");
            }
      } catch (error) {
            res.status(500).send("Internal Server Error");
      }
});

// Global error handler
app.use((err, req, res, next) => {
      res.status(500).send("Something went wrong!");
});

// 404 handler
app.use((req, res) => {
      res.status(404).send("Not Found");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
      console.log(`Privus API running on port ${PORT}`);
});

// Graceful shutdown
process.on('SIGINT', async () => {
      await prisma.$disconnect();
      process.exit(0);
});
