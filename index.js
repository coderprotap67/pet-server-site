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

const app = express();
const port = process.env.PORT || 5000;

app.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true,
  })
);

app.use(express.json());

const uri = process.env.MONGODB_URI;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});


// ================= JWT VERIFY =================

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
    await client.connect();

    console.log("MongoDB Connected");

    const db = client.db("simpleCurd");

    const usersCollection = db.collection("users");
    const petsCollection = db.collection("pets");
    const adoptionCollection = db.collection("adoptions");



    // ================= REGISTER =================

    app.post("/register", async (req, res) => {
      try {
        const { name, email, password, photo } = req.body;

        const existingUser = await usersCollection.findOne({
          email,
        });

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

        await usersCollection.insertOne(user);

        const token = jwt.sign(
          { email },
          process.env.JWT_SECRET,
          {
            expiresIn: "7d",
          }
        );

        res.send({
          success: true,
          token,
          user,
        });

      } catch (err) {
        console.log(err);

        res.status(500).send({
          success: false,
          message: "Register Failed",
        });
      }
    });



    // ================= LOGIN =================

    app.post("/login", async (req, res) => {
      try {
        const { email, password } = req.body;

        const user = await usersCollection.findOne({
          email,
        });

        if (!user) {
          return res.status(404).send({
            success: false,
            message: "User not found",
          });
        }

        const isMatch = await bcrypt.compare(
          password,
          user.password
        );

        if (!isMatch) {
          return res.status(400).send({
            success: false,
            message: "Wrong password",
          });
        }

        const token = jwt.sign(
          { email: user.email },
          process.env.JWT_SECRET,
          {
            expiresIn: "7d",
          }
        );

        res.send({
          success: true,
          token,
          user,
        });

      } catch (err) {
        console.log(err);

        res.status(500).send({
          success: false,
          message: "Login Failed",
        });
      }
    });



    // ================= CURRENT USER =================

    app.get("/me", verifyToken, async (req, res) => {
      try {

        const user = await usersCollection.findOne({
          email: req.user.email,
        });

        res.send({
          success: true,
          data: user,
        });

      } catch (err) {
        console.log(err);
      }
    });



    // ================= GET ALL PETS =================

    app.get("/pets", async (req, res) => {
      try {

        const { search, species } = req.query;

        let query = {};

        if (search) {
          query.petName = {
            $regex: search,
            $options: "i",
          };
        }

        if (species) {
          query.species = {
            $in: species.split(","),
          };
        }

        const result = await petsCollection
          .find(query)
          .sort({ createdAt: -1 })
          .toArray();

        res.send({
          success: true,
          data: result,
        });

      } catch (err) {
        console.log(err);
      }
    });



    // ================= GET SINGLE PET =================

    app.get("/pets/:id", async (req, res) => {
      try {

        const id = req.params.id.trim();

        let pet = null;

        // STRING ID CHECK
        pet = await petsCollection.findOne({
          _id: id,
        });

        // OBJECT ID CHECK
        if (!pet && ObjectId.isValid(id)) {
          pet = await petsCollection.findOne({
            _id: new ObjectId(id),
          });
        }

        if (!pet) {
          return res.status(404).send({
            success: false,
            message: "Pet not found",
          });
        }

        res.send({
          success: true,
          data: pet,
        });

      } catch (err) {
        console.log(err);

        res.status(500).send({
          success: false,
          message: "Server Error",
        });
      }
    });



    // ================= ADD PET =================

    app.post("/pets", verifyToken, async (req, res) => {
      try {

        const pet = {
          ...req.body,
          ownerEmail: req.user.email,
          status: "available",
          createdAt: new Date(),
        };

        const result = await petsCollection.insertOne(pet);

        res.send({
          success: true,
          message: "Pet added successfully",
          result,
        });

      } catch (err) {
        console.log(err);
      }
    });



    // ================= MY LISTINGS =================

    app.get("/my-listings/:email", verifyToken, async (req, res) => {
      try {

        const result = await petsCollection.find({
          ownerEmail: req.params.email,
        }).toArray();

        res.send({
          success: true,
          data: result,
        });

      } catch (err) {
        console.log(err);
      }
    });



    // ================= UPDATE PET =================

    app.put("/pets/:id", verifyToken, async (req, res) => {
      try {

        const result = await petsCollection.updateOne(
          {
            _id: new ObjectId(req.params.id),
          },
          {
            $set: req.body,
          }
        );

        res.send({
          success: true,
          message: "Pet updated",
          result,
        });

      } catch (err) {
        console.log(err);
      }
    });



    // ================= DELETE PET =================

    app.delete("/pets/:id", verifyToken, async (req, res) => {
      try {

        const result = await petsCollection.deleteOne({
          _id: new ObjectId(req.params.id),
        });

        res.send({
          success: true,
          message: "Pet deleted",
          result,
        });

      } catch (err) {
        console.log(err);
      }
    });



    // ================= ADOPTION REQUEST =================

    app.post("/adoptions", verifyToken, async (req, res) => {
      try {

        const data = {
          ...req.body,
          userEmail: req.user.email,
          status: "pending",
          createdAt: new Date(),
        };

        // OWNER CANNOT ADOPT OWN PET
        const pet = await petsCollection.findOne({
          _id: req.body.petId,
        });

        if (pet?.ownerEmail === req.user.email) {
          return res.status(400).send({
            success: false,
            message: "Owner cannot adopt own pet",
          });
        }

        // PET ALREADY ADOPTED
        if (pet?.status === "adopted") {
          return res.status(400).send({
            success: false,
            message: "Pet already adopted",
          });
        }

        const result = await adoptionCollection.insertOne(data);

        res.send({
          success: true,
          message: "Adoption request sent",
          result,
        });

      } catch (err) {
        console.log(err);
      }
    });



    // ================= MY REQUESTS =================

    app.get("/my-requests", verifyToken, async (req, res) => {
      try {

        const result = await adoptionCollection.find({
          userEmail: req.user.email,
        }).toArray();

        res.send({
          success: true,
          data: result,
        });

      } catch (err) {
        console.log(err);
      }
    });



    // ================= CANCEL REQUEST =================

    app.delete("/adoptions/:id", verifyToken, async (req, res) => {
      try {

        const result = await adoptionCollection.deleteOne({
          _id: new ObjectId(req.params.id),
        });

        res.send({
          success: true,
          message: "Request cancelled",
          result,
        });

      } catch (err) {
        console.log(err);
      }
    });



    // ================= GET PET REQUESTS =================

    app.get("/requests/pet/:petId", verifyToken, async (req, res) => {
      try {

        const result = await adoptionCollection.find({
          petId: req.params.petId,
        }).toArray();

        res.send({
          success: true,
          data: result,
        });

      } catch (err) {
        console.log(err);
      }
    });



    // ================= APPROVE / REJECT =================

    app.patch("/requests/:id/process", verifyToken, async (req, res) => {
      try {

        const { action } = req.body;

        const request = await adoptionCollection.findOne({
          _id: new ObjectId(req.params.id),
        });

        if (!request) {
          return res.status(404).send({
            success: false,
            message: "Request not found",
          });
        }

        await adoptionCollection.updateOne(
          {
            _id: new ObjectId(req.params.id),
          },
          {
            $set: {
              status: action,
            },
          }
        );

        // APPROVED
        if (action === "approved") {

          // PET ADOPTED
          await petsCollection.updateOne(
            {
              _id: request.petId,
            },
            {
              $set: {
                status: "adopted",
              },
            }
          );

          // REJECT OTHERS
          await adoptionCollection.updateMany(
            {
              petId: request.petId,
              _id: {
                $ne: new ObjectId(req.params.id),
              },
            },
            {
              $set: {
                status: "rejected",
              },
            }
          );
        }

        res.send({
          success: true,
          message: "Request processed",
        });

      } catch (err) {
        console.log(err);
      }
    });



    // ================= ROOT =================

    app.get("/", (req, res) => {
      res.send({
        message: "Pet Adoption Server Running",
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