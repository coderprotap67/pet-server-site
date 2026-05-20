require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");

const app = express();
const port = process.env.PORT || 5000;

app.use(cors({
  origin: "http://localhost:3000",
  credentials: true,
}));

app.use(express.json());

const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).send({ success: false, message: "Unauthorized Access" });

  const token = authHeader.split(" ")[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).send({ success: false, message: "Forbidden Access" });
    req.user = decoded;
    next();
  });
};

async function run() {
  try {
    await client.connect();
    console.log("MongoDB Connected");
    const db = client.db("simpleCurd");
    const usersCollection = db.collection("users");
    const petsCollection = db.collection("pets");
    const adoptionCollection = db.collection("adoptions");

    // --- রেজিস্ট্রেশন রাউট ---
    app.post("/register", async (req, res) => {
      try {
        const { name, email, password, photo } = req.body;
        const existingUser = await usersCollection.findOne({ email });
        if (existingUser) return res.status(400).send({ success: false, message: "User already exists" });

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = { name, email, password: hashedPassword, photo, role: "user", createdAt: new Date() };
        await usersCollection.insertOne(user);
        
        const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: "7d" });
        res.status(201).send({ success: true, message: "Registration successful", token, user });
      } catch (error) {
        res.status(500).send({ success: false, message: "Server error during registration" });
      }
    });

    // --- লগইন রাউট ---
    app.post("/login", async (req, res) => {
      try {
        const { email, password } = req.body;
        const user = await usersCollection.findOne({ email });
        if (!user) return res.status(404).send({ success: false, message: "User not found" });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).send({ success: false, message: "Invalid email or password" });

        const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET, { expiresIn: "7d" });
        res.send({ success: true, message: "Login successful", token, user });
      } catch (error) {
        res.status(500).send({ success: false, message: "Server error during login" });
      }
    });

    // --- অন্যান্য সব রাউট আগের মতোই ---
    app.post("/pets", verifyToken, async (req, res) => {
      const pet = { ...req.body, status: "available", createdAt: new Date(), ownerEmail: req.user.email };
      const result = await petsCollection.insertOne(pet);
      res.send({ success: true, message: "Pet added successfully", result });
    });

    app.get("/pets", async (req, res) => {
      const result = await petsCollection.find().sort({ createdAt: -1 }).toArray();
      res.send({ success: true, data: result });
    });

    app.get("/pets/:id", async (req, res) => {
      const result = await petsCollection.findOne({ _id: new ObjectId(req.params.id) });
      res.send({ success: true, data: result });
    });

    app.get("/my-listings/:email", verifyToken, async (req, res) => {
      const result = await petsCollection.find({ ownerEmail: req.params.email }).toArray();
      res.send({ success: true, data: result });
    });

    app.put("/pets/:id", verifyToken, async (req, res) => {
      const result = await petsCollection.updateOne({ _id: new ObjectId(req.params.id) }, { $set: req.body });
      res.send({ success: true, message: "Pet updated successfully", result });
    });

    app.delete("/pets/:id", verifyToken, async (req, res) => {
      const result = await petsCollection.deleteOne({ _id: new ObjectId(req.params.id) });
      res.send({ success: true, message: "Pet deleted successfully", result });
    });

    app.post("/adoptions", verifyToken, async (req, res) => {
      const adoptionData = { ...req.body, status: "pending", createdAt: new Date(), userEmail: req.user.email };
      const result = await adoptionCollection.insertOne(adoptionData);
      res.send({ success: true, message: "Adoption request sent", result });
    });

    app.get("/my-requests/:email", verifyToken, async (req, res) => {
      const result = await adoptionCollection.find({ userEmail: req.params.email }).toArray();
      res.send({ success: true, data: result });
    });

    app.get("/", (req, res) => res.send({ message: "Pet Adoption Server Running 🚀" }));

  } catch (error) {
    console.error(error);
  }
}
run().catch(console.dir);

app.listen(port, () => console.log(`Server running on port ${port}`));