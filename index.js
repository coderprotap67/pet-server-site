require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const app = express();
const port = process.env.PORT || 5000;
app.use(cors());
app.use(express.json());
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

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
async function run() {
  try {
    const usersCollection = client.db("petDB").collection("users");
    const petsCollection = client.db("petDB").collection("pets");
    const adoptionCollection = client.db("petDB").collection("adoptions");
    app.post("/register", async (req, res) => {
      try {
        const { name, email, password, photo } = req.body;
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
          photo,
          role: "user",
          createdAt: new Date(),
        };
        const result = await usersCollection.insertOne(user);
        const token = jwt.sign(
          {
            email,
          },
          process.env.JWT_SECRET,
          {
            expiresIn: "7d",
          }
        );
        res.send({
          success: true,
          message: "Registration successful",
          token,
          result,
        });
      } catch (error) {
        res.status(500).send({
          success: false,
          message: error.message,
        });
      }
    });

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
            message: "Invalid password",
          });
        }
        const token = jwt.sign(
          {
            email: user.email,
          },
          process.env.JWT_SECRET,
          {
            expiresIn: "7d",
          }
        );
        res.send({
          success: true,
          message: "Login successful",
          token,
          user,
        });
      } catch (error) {
        res.status(500).send({
          success: false,
          message: error.message,
        });
      }
    });

    app.post("/pets", verifyToken, async (req, res) => {
      try {
        const pet = req.body;
        pet.status = "available";
        pet.createdAt = new Date();
        const result = await petsCollection.insertOne(pet);
        res.send({
          success: true,
          message: "Pet added successfully",
          result,
        });
      } catch (error) {
        res.status(500).send({
          success: false,
          message: error.message,
        });
      }
    });


    app.get("/pets", async (req, res) => {
      try {
        const result = await petsCollection
          .find()
          .sort({ createdAt: -1 })
          .toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({
          success: false,
          message: error.message,
        });

      }
    });
    app.get("/pets/:id", async (req, res) => {
      try {
        const id = req.params.id;
        const result = await petsCollection.findOne({
          _id: new ObjectId(id),
        });
        res.send(result);
      } catch (error) {
        res.status(500).send({
          success: false,
          message: error.message,
        });
      }
    });

    app.get("/my-listings/:email", verifyToken, async (req, res) => {
      try {
        const email = req.params.email;
        const result = await petsCollection
          .find({
            ownerEmail: email,
          })
          .toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({
          success: false,
          message: error.message,
        });
      }
    });


    app.put("/pets/:id", verifyToken, async (req, res) => {
      try {
        const id = req.params.id;
        const updatedPet = req.body;
        const result = await petsCollection.updateOne(
          {
            _id: new ObjectId(id),
          },
          {
            $set: updatedPet,
          }
        );
        res.send({
          success: true,
          message: "Pet updated successfully",
          result,
        });
      } catch (error) {
        res.status(500).send({
          success: false,
          message: error.message,
        });
      }
    });
    app.delete("/pets/:id", verifyToken, async (req, res) => {
      try {
        const id = req.params.id;
        const result = await petsCollection.deleteOne({
          _id: new ObjectId(id),
        });
        res.send({
          success: true,
          message: "Pet deleted successfully",
          result,
        });
      } catch (error) {
        res.status(500).send({
          success: false,
          message: error.message,
        });
      }
    });
    app.post("/adoptions", verifyToken, async (req, res) => {
      try {
        const adoptionData = req.body;
        adoptionData.status = "pending";
        adoptionData.createdAt = new Date();
        const result = await adoptionCollection.insertOne(adoptionData);
        res.send({
          success: true,
          message: "Adoption request sent",
          result,
        });
      } catch (error) {
        res.status(500).send({
          success: false,
          message: error.message,
        });

      }
    });

    app.get("/my-requests/:email", verifyToken, async (req, res) => {
      try {
        const email = req.params.email;
        const result = await adoptionCollection
          .find({
            userEmail: email,
          })
          .toArray();
      res.send(result);
      } catch (error) {
        res.status(500).send({
          success: false,
          message: error.message,
        });
      }
    });
    app.get("/", (req, res) => {
      res.send("Pet Adoption Server Running");
    });

    await client.connect();
    console.log("MongoDB Connected");
  } finally {
  }
}
run().catch(console.dir);
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});






































// const express = require('express');
// const { MongoClient, ServerApiVersion } = require('mongodb');
// const uri =MONGODB_URI;
// const app = express();
// const PORT = process.env.PORT || 5000;

// const client = new MongoClient(uri, {
//   serverApi: {
//     version: ServerApiVersion.v1,
//     strict: true,
//     deprecationErrors: true,
//   }
// });


// async function run() {
//   try {
//     await client.connect();
//     await client.db("admin").command({ ping: 1 });
//     console.log("Pinged your deployment. You successfully connected to MongoDB!");
//   } finally {
//     await client.close();
//   }
// }
// run().catch(console.dir);

// app.get('/', (req, res) => {
//   res.send('Hello, World!');
// });

// app.listen(PORT, () => {
//   console.log(`Server is running on port ${PORT}`);
// });