const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// ==========================================
// 1. MIDDLEWARE CONFIGURATION
// ==========================================
app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: process.env.CLIENT_URL || 'http://localhost:3000',
  credentials: true
}));

// ==========================================
// 2. MONGO_DB CONNECTION INITIALIZATION
// ==========================================
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB cluster linked successfully.'))
  .catch((err) => console.error('Database connection breakdown:', err));

// ==========================================
// 3. DATABASE SCHEMA & MODEL DEFINITIONS
// ==========================================

// Pet Schema
const petSchema = new mongoose.Schema({
  name: { type: String, required: true },
  species: { type: String, required: true, enum: ['Dog', 'Cat', 'Bird', 'Rabbit', 'Other'] },
  breed: { type: String, required: true },
  age: { type: Number, required: true },
  gender: { type: String, required: true, enum: ['Male', 'Female'] },
  imageUrl: { type: String, required: true },
  healthStatus: { type: String, required: true },
  vaccinationStatus: { type: String, required: true },
  location: { type: String, required: true },
  adoptionFee: { type: Number, required: true, default: 0 },
  description: { type: String, required: true },
  ownerEmail: { type: String, required: true, index: true },
  status: { type: String, required: true, enum: ['available', 'adopted'], default: 'available' }
}, { timestamps: true });

const Pet = mongoose.model('Pet', petSchema);

// Adoption Request Schema
const adoptionRequestSchema = new mongoose.Schema({
  petId: { type: mongoose.Schema.Types.ObjectId, ref: 'Pet', required: true },
  petName: { type: String, required: true },
  ownerEmail: { type: String, required: true, index: true },
  requesterName: { type: String, required: true },
  requesterEmail: { type: String, required: true, index: true },
  pickupDate: { type: Date, required: true },
  message: { type: String, required: true },
  status: { type: String, required: true, enum: ['pending', 'approved', 'rejected'], default: 'pending' }
}, { timestamps: true });

const AdoptionRequest = mongoose.model('AdoptionRequest', adoptionRequestSchema);

// Wishlist Schema
const wishlistSchema = new mongoose.Schema({
  userEmail: { type: String, required: true, index: true },
  petId: { type: mongoose.Schema.Types.ObjectId, ref: 'Pet', required: true }
}, { timestamps: true });
wishlistSchema.index({ userEmail: 1, petId: 1 }, { unique: true });

const Wishlist = mongoose.model('Wishlist', wishlistSchema);

// User Schema (Simulating Better-Auth Session Verification Layout)
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  photoUrl: { type: String }
});
const User = mongoose.model('User', userSchema);

// ==========================================
// 4. SECURITY & AUTHENTICATION MIDDLEWARE
// ==========================================
const verifyToken = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ success: false, message: "Access denied. Token missing." });
  }
  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified; 
    next();
  } catch (error) {
    return res.status(403).json({ success: false, message: "Invalid or expired token security layer." });
  }
};

// ==========================================
// 5. API ROUTE ROUTERS (CRUD & BUSINESS LOGIC)
// ==========================================

// --- AUTH ROUTING ENDPOINTS ---
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, confirmPassword, photoUrl } = req.body;
    
    if (password.length < 6 || !/[A-Z]/.test(password) || !/[a-z]/.test(password)) {
      return res.status(400).json({ message: "Password structural constraints violated." });
    }
    if (password !== confirmPassword) {
      return res.status(400).json({ message: "Passwords mismatch values." });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: "Email mapping collision." });

    const newUser = new User({ name, email, password, photoUrl });
    await newUser.save();

    const token = jwt.sign({ id: newUser._id, email: newUser.email, name: newUser.name, photoUrl: newUser.photoUrl }, process.env.JWT_SECRET, { expiresIn: '7d' });
    
    res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'none', maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.status(201).json({ success: true, user: { name, email, photoUrl } });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || user.password !== password) {
      return res.status(401).json({ message: "Invalid cryptographic credentials matches." });
    }

    const token = jwt.sign({ id: user._id, email: user.email, name: user.name, photoUrl: user.photoUrl }, process.env.JWT_SECRET, { expiresIn: '7d' });
    
    res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'none', maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.status(200).json({ success: true, user: { name: user.name, email: user.email, photoUrl: user.photoUrl } });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get('/api/auth/me', verifyToken, (req, res) => {
  res.status(200).json({ success: true, user: req.user });
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.status(200).json({ success: true, message: "Session wiped successfully." });
});


// --- PET MANAGEMENT ENDPOINTS ---
app.get('/api/pets', async (req, res) => {
  try {
    const { search, species } = req.query;
    let queryPayload = {};

    if (search) {
      queryPayload.name = { $regex: search, $options: 'i' };
    }
    if (species) {
      queryPayload.species = { $in: species.split(',') };
    }

    const matchedPets = await Pet.find(queryPayload).sort({ createdAt: -1 });
    res.status(200).json({ success: true, data: matchedPets });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get('/api/pets/my-listings', verifyToken, async (req, res) => {
  try {
    const listings = await Pet.find({ ownerEmail: req.user.email });
    res.status(200).json({ success: true, data: listings });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get('/api/pets/:id', async (req, res) => {
  try {
    const pet = await Pet.findById(req.params.id);
    if (!pet) return res.status(404).json({ message: "Asset profile missing." });
    res.status(200).json({ success: true, data: pet });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/pets', verifyToken, async (req, res) => {
  try {
    const newPet = new Pet({ ...req.body, ownerEmail: req.user.email });
    await newPet.save();
    res.status(201).json({ success: true, data: newPet });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.put('/api/pets/:id', verifyToken, async (req, res) => {
  try {
    const pet = await Pet.findById(req.params.id);
    if (!pet) return res.status(404).json({ message: "Pet missing." });
    if (pet.ownerEmail !== req.user.email) return res.status(403).json({ message: "Access forbidden." });

    const updatedPet = await Pet.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.status(200).json({ success: true, data: updatedPet });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.delete('/api/pets/:id', verifyToken, async (req, res) => {
  try {
    const pet = await Pet.findById(req.params.id);
    if (!pet) return res.status(404).json({ message: "Pet missing." });
    if (pet.ownerEmail !== req.user.email) return res.status(403).json({ message: "Access forbidden." });

    await Pet.findByIdAndDelete(req.params.id);
    res.status(200).json({ success: true, message: "Asset document eliminated." });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


// --- CRITICAL ADOPTION APPLICATION & CASCADE SINGLE-APPROVAL ROUTING ---
app.post('/api/requests', verifyToken, async (req, res) => {
  try {
    const { petId, pickupDate, message } = req.body;
    const pet = await Pet.findById(petId);
    if (!pet) return res.status(404).json({ message: "Pet asset not found." });

    // Business Constraint Rule Implementation
    if (pet.ownerEmail === req.user.email) {
      return res.status(403).json({ message: "Action forbidden: You cannot apply to adopt your own listed pet." });
    }
    if (pet.status === 'adopted') {
      return res.status(400).json({ message: "This pet has already been adopted." });
    }

    const newRequest = new AdoptionRequest({
      petId,
      petName: pet.name,
      ownerEmail: pet.ownerEmail,
      requesterName: req.user.name,
      requesterEmail: req.user.email,
      pickupDate,
      message
    });

    await newRequest.save();
    res.status(201).json({ success: true, data: newRequest });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get('/api/requests/my-requests', verifyToken, async (req, res) => {
  try {
    const claims = await AdoptionRequest.find({ requesterEmail: req.user.email });
    res.status(200).json({ success: true, data: claims });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get('/api/requests/pet/:petId', verifyToken, async (req, res) => {
  try {
    const requests = await AdoptionRequest.find({ petId: req.params.petId });
    res.status(200).json({ success: true, data: requests });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Single-Approval Policy Core Pipeline Execution (Using Transaction Sim)
app.patch('/api/requests/:requestId/process', verifyToken, async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const { requestId } = req.params;
    const { action } = req.body; // Expecting strings: 'approved' or 'rejected'

    const targetRequest = await AdoptionRequest.findById(requestId).session(session);
    if (!targetRequest) {
      await session.abortTransaction();
      return res.status(404).json({ message: "Adoption claim request not found." });
    }
    if (targetRequest.ownerEmail !== req.user.email) {
      await session.abortTransaction();
      return res.status(403).json({ message: "Unauthorized handling of listing requests." });
    }
    if (targetRequest.status !== 'pending') {
      await session.abortTransaction();
      return res.status(400).json({ message: "This request has already been processed." });
    }

    if (action === 'rejected') {
      targetRequest.status = 'rejected';
      await targetRequest.save({ session });
      await session.commitTransaction();
      session.endSession();
      return res.status(200).json({ success: true, message: "Request successfully rejected." });
    }

    if (action === 'approved') {
      // 1. Update targeting request status mapping
      targetRequest.status = 'approved';
      await targetRequest.save({ session });

      // 2. Cascade state modification across targeted Pet document
      await Pet.findByIdAndUpdate(targetRequest.petId, { status: 'adopted' }, { session });

      // 3. Atomically auto-reject all other alternative requests pending on the same pet
      await AdoptionRequest.updateMany(
        { petId: targetRequest.petId, _id: { $ne: targetRequest._id }, status: 'pending' },
        { status: 'rejected' },
        { session }
      );

      await session.commitTransaction();
      session.endSession();
      return res.status(200).json({ success: true, message: "Request approved. Outstandings rejected automatically." });
    }
  } catch (error) {
    await session.abortTransaction();
    session.endSession();
    res.status(500).json({ message: error.message });
  }
});

app.delete('/api/requests/:id', verifyToken, async (req, res) => {
  try {
    const request = await AdoptionRequest.findById(req.params.id);
    if (!request) return res.status(404).json({ message: "Request missing." });
    if (request.requesterEmail !== req.user.email) return res.status(403).json({ message: "Unauthorized cancel action." });

    await AdoptionRequest.findByIdAndDelete(req.params.id);
    res.status(200).json({ success: true, message: "Claim retracted." });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


// --- WISHLIST MANAGEMENT ENDPOINTS ---
app.get('/api/wishlist', verifyToken, async (req, res) => {
  try {
    const items = await Wishlist.find({ userEmail: req.user.email }).populate('petId');
    res.status(200).json({ success: true, data: items });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/wishlist', verifyToken, async (req, res) => {
  try {
    const { petId } = req.body;
    const newWishItem = new Wishlist({ userEmail: req.user.email, petId });
    await newWishItem.save();
    res.status(201).json({ success: true, data: newWishItem });
  } catch (err) {
    if (err.code === 11000) return res.status(400).json({ message: "Asset already marked inside wishlist array." });
    res.status(500).json({ message: err.message });
  }
});

app.delete('/api/wishlist/:petId', verifyToken, async (req, res) => {
  try {
    await Wishlist.findOneAndDelete({ userEmail: req.user.email, petId: req.params.petId });
    res.status(200).json({ success: true, message: "Removed from bookmark index successfully." });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


// ==========================================
// 6. SERVER BOOT INITIALIZATION
// ==========================================
app.listen(PORT, () => {
  console.log(`Pet Adoption Backend Engine executing smoothly over port ${PORT}`);
});