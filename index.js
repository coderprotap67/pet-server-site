require("dotenv").config();

const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const {
  MongoClient,
  ServerApiVersion,
  ObjectId,
} = require("mongodb");

const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const session = require("express-session");

const app = express();
const port = process.env.PORT || 5000;

// ---------------- MIDDLEWARE ----------------
app.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true,
  })
);

app.use(express.json());

// ---------------- SESSION ----------------
app.use(
  session({
    secret: "pet-secret",
    resave: false,
    saveUninitialized: true,
  })
);

app.use(passport.initialize());
app.use(passport.session());

// ---------------- MONGODB ----------------
const uri = process.env.MONGODB_URI;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// ---------------- JWT VERIFY ----------------
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).send({
      success: false,
      message: "Unauthorized Access",
    });
  }

  const token = authHeader.split(" ")[1];

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).send({
        success: false,
        message: "Forbidden Access",
      });
    }

    req.user = decoded;
    next();
  });
};

// ---------------- GOOGLE STRATEGY ----------------
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:5000/auth/google/callback",
    },
    async (accessToken, refreshToken, profile, done) => {
      const user = {
        name: profile.displayName,
        email: profile.emails[0].value,
        image: profile.photos[0].value,
      };

      return done(null, user);
    }
  )
);

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// ---------------- MAIN APP ----------------
async function run() {
  try {
    await client.connect();

    console.log("MongoDB Connected");

    const db = client.db("simpleCurd");

    const usersCollection = db.collection("users");
    const petsCollection = db.collection("pets");
    const adoptionCollection = db.collection("adoptions");

    // ---------------- REGISTER ----------------
    app.post("/register", async (req, res) => {
      try {
        const { name, email, password, image } = req.body;

        const existingUser = await usersCollection.findOne({ email });

        if (existingUser) {
          return res.status(400).send({
            success: false,
            message: "User already exists",
          });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = {
          name,
          email,
          password: hashedPassword,
          image,
          role: "user",
          createdAt: new Date(),
        };

        await usersCollection.insertOne(user);

        const token = jwt.sign(
          { email },
          process.env.JWT_SECRET,
          { expiresIn: "7d" }
        );

        res.send({ success: true, token, user });

      } catch (err) {
        res.status(500).send({
          success: false,
          message: "Register Failed",
        });
      }
    });

    // ---------------- LOGIN ----------------
    app.post("/login", async (req, res) => {
      try {
        const { email, password } = req.body;

        const user = await usersCollection.findOne({ email });

        if (!user) {
          return res.status(404).send({
            success: false,
            message: "User not found",
          });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
          return res.status(400).send({
            success: false,
            message: "Wrong password",
          });
        }

        const token = jwt.sign(
          { email: user.email },
          process.env.JWT_SECRET,
          { expiresIn: "7d" }
        );

        res.send({ success: true, token, user });

      } catch (err) {
        res.status(500).send({
          success: false,
          message: "Login Failed",
        });
      }
    });

    // ---------------- GOOGLE LOGIN ----------------
    app.get(
      "/auth/google",
      passport.authenticate("google", { scope: ["profile", "email"] })
    );

    app.get(
      "/auth/google/callback",
      passport.authenticate("google", {
        failureRedirect: "http://localhost:3000/login",
      }),
      async (req, res) => {
        const gUser = req.user;

        let user = await usersCollection.findOne({ email: gUser.email });

        if (!user) {
          const result = await usersCollection.insertOne({
            ...gUser,
            password: "",
            provider: "google",
            createdAt: new Date(),
          });

          user = { ...gUser, _id: result.insertedId };
        }

        const token = jwt.sign(
          { email: user.email },
          process.env.JWT_SECRET,
          { expiresIn: "7d" }
        );

        res.redirect(`http://localhost:3000?token=${token}`);
      }
    );

    // ---------------- GOOGLE SUCCESS ----------------
    app.get("/auth/google/success", (req, res) => {
      if (req.user) {
        res.send({
          success: true,
          user: req.user,
        });
      } else {
        res.status(401).send({
          success: false,
          message: "Not authorized",
        });
      }
    });

    // ---------------- CURRENT USER ----------------
    app.get("/me", verifyToken, async (req, res) => {
      const user = await usersCollection.findOne({ email: req.user.email });

      res.send({
        success: true,
        data: user,
      });
    });

    // ---------------- PETS ----------------
    app.get("/pets", async (req, res) => {
      const result = await petsCollection.find().toArray();

      res.send({
        success: true,
        data: result,
      });
    });

    app.get("/pets/:id", async (req, res) => {
      const id = req.params.id;

      let pet = await petsCollection.findOne({ _id: id });

      if (!pet && ObjectId.isValid(id)) {
        pet = await petsCollection.findOne({
          _id: new ObjectId(id),
        });
      }

      res.send({
        success: true,
        data: pet,
      });
    });

    app.post("/pets", verifyToken, async (req, res) => {
      const pet = {
        ...req.body,
        ownerEmail: req.user.email,
        createdAt: new Date(),
      };

      await petsCollection.insertOne(pet);

      res.send({
        success: true,
      });
    });

    // ---------------- ROOT ----------------
    app.get("/", (req, res) => {
      res.send({
        message: "Server Running",
      });
    });

  } catch (err) {
    console.log(err);
  }
}

run().catch(console.dir);

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});