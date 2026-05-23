require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const session = require("express-session");

const app = express();
app.use(cors({ 
  origin: process.env.CLIENT_URL, 
  credentials: true 
}));
app.use(session({
  secret: "pet-secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === "production", 
    sameSite: process.env.NODE_ENV === "production" ? "none" : "lax" 
  }
}));
app.use(passport.initialize());
app.use(passport.session());
const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri, {
  serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true },
});

let db, usersCollection, petsCollection, adoptionCollection;

async function connectDB() {
  if (!db) {
    await client.connect();
    db = client.db("simpleCurd");
    usersCollection = db.collection("users");
    petsCollection = db.collection("pets");
    adoptionCollection = db.collection("adoptions");
    console.log("MongoDB Connected Successfully");
  }
}
async function connectDB() {
  if (!db) {
    console.log("Connecting to DB..."); 
    await client.connect();
    db = client.db("simpleCurd");
    usersCollection = db.collection("users");
    petsCollection = db.collection("pets");
    adoptionCollection = db.collection("adoptions");
    console.log("MongoDB Connected Successfully");
  }
}

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: `${process.env.GOOGLE_CALLBACK_URL}/auth/google/callback`,
}, async (accessToken, refreshToken, profile, done) => {
  const user = { name: profile.displayName, email: profile.emails[0].value, image: profile.photos[0].value };
  return done(null, user);
}));
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

app.get("/", (req, res) => res.send({ message: "Server Running" }));

app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get("/auth/google/callback", passport.authenticate("google", { failureRedirect: `${process.env.CLIENT_URL}/login` }), async (req, res) => {
  const gUser = req.user;
  let user = await usersCollection.findOne({ email: gUser.email });
  if (!user) {
    await usersCollection.insertOne({ ...gUser, password: "", provider: "google", createdAt: new Date() });
    user = await usersCollection.findOne({ email: gUser.email });
  }
  const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET, { expiresIn: "7d" });
  res.redirect(`${process.env.CLIENT_URL}/login?token=${token}`);
});

app.post("/register", async (req, res) => {
  try {
    const { name, email, password, image } = req.body;
    const existingUser = await usersCollection.findOne({ email });
    if (existingUser) return res.status(400).send({ success: false, message: "User already exists" });
    const hashedPassword = await bcrypt.hash(password, 10);
    await usersCollection.insertOne({ name, email, password: hashedPassword, image, role: "user", createdAt: new Date() });
    const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: "7d" });
    res.send({ success: true, token, user: { name, email, image } });
  } catch (err) { res.status(500).send({ success: false, message: "Register Failed" }); }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await usersCollection.findOne({ email });
    if (!user) return res.status(404).send({ success: false, message: "User not found" });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).send({ success: false, message: "Wrong password" });
    const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET, { expiresIn: "7d" });
    res.send({ success: true, token, user });
  } catch (err) { res.status(500).send({ success: false, message: "Login Failed" }); }
});

app.get("/me", (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).send({ success: false, message: "Unauthorized Access" });
    const token = authHeader.split(" ")[1];
    jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
        if (err) return res.status(403).send({ success: false, message: "Forbidden Access" });
        const user = await usersCollection.findOne({ email: decoded.email });
        res.send({ success: true, data: user });
    });
});

app.get("/pets", async (req, res) => {
  const result = await petsCollection.find().toArray();
  res.send({ success: true, data: result });
});

app.post("/pets", (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).send({ success: false, message: "Unauthorized Access" });
    const token = authHeader.split(" ")[1];
    jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
        if (err) return res.status(403).send({ success: false, message: "Forbidden Access" });
        const pet = { ...req.body, ownerEmail: decoded.email, createdAt: new Date() };
        await petsCollection.insertOne(pet);
        res.send({ success: true });
    });
});

app.post("/adoptions", (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).send({ success: false, message: "Unauthorized Access" });
    const token = authHeader.split(" ")[1];
    jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
        if (err) return res.status(403).send({ success: false, message: "Forbidden Access" });
        const adoptionData = { ...req.body, requesterEmail: decoded.email, status: "pending", createdAt: new Date() };
        if (adoptionData.petId && ObjectId.isValid(adoptionData.petId)) adoptionData.petId = new ObjectId(adoptionData.petId);
        await adoptionCollection.insertOne(adoptionData);
        res.send({ success: true, message: "Request sent successfully!" });
    });
});

module.exports = app;