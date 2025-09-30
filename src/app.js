const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
const dotenv = require("dotenv");
const passport = require("passport");
const session = require("express-session");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const User = require("./models/user.model.js");
const jwt = require("jsonwebtoken");
const authenticate = require("./middlewares/auth.middleware.js");
const upload = require("./middlewares/upload.js");
const { Readable } = require('stream'); // For buffer-to-stream conversion in Cloudinary
const cloudinary = require("cloudinary"); // Import Cloudinary v2
const MongoStore = require('connect-mongo');
// import "./auth/passport.js";

dotenv.config();

const app = express();

// Cloudinary config (move to a separate file if needed)
cloudinary.v2.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});
// https://band-wagon-iota.vercel.app
        // Middleware
app.use(cors({
    origin: "https://band-wagon-iota.vercel.app",  // Your frontend URL
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
}));
app.use(express.json());
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ limit: "50mb", extended: true, parameterLimit: 50000 }));
app.use(bodyParser.json());

// Replace your session setup with:
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URL,
    collectionName: 'sessions',  // Optional: custom collection
  }),
  cookie: {
    secure: true,  // HTTPS only in prod
    maxAge: 24 * 60 * 60 * 1000,  // 1 day
  },
}));

        // Setup passport
app.use(passport.initialize());
app.use(passport.session());

passport.use(
    new GoogleStrategy({
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: "/auth/google/callback",
        scope: ["profile", "email"]
    },
    async (accessToken, refreshToken, profile, done) => {
        try {
            let user = await User.findOne({ googleId: profile.id });

            if (!user) {
                user = new User({
                    googleId: profile.id,
                    username: profile.displayName,
                    email: profile.emails[0].value,
                    password: profile.displayName,  // Note: This is insecure; consider hashing or removing
                    profileImage: profile.photos[0].value,
                });
                await user.save();
            }

            const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1d" });

            return done(null, { user, token });
        } catch (error) {
            return done(error, null); 
        }
    }
)
);

passport.serializeUser((data, done) => {
        done(null, data);
})

passport.deserializeUser((data, done) => {
        done(null, data);
})

        // initial google auth login
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get("/auth/google/callback", passport.authenticate("google", { 
        successRedirect: "https://band-wagon-iota.vercel.app/home",
        failureRedirect: "https://band-wagon-iota.vercel.app/login", 
        failWithError: "https://band-wagon-iota.vercel.app/login",
}))

app.get("/login/success", async (req, res) => {
        if (req.user) {
                res.status(200).json({ message: "Login successful", user: req.user, accessToken: req.user.token });
        } else {
                res.status(401).json({ message: "Login failed" });
        }
})

app.get("/logout", (req, res, next) => {
        req.logout(function(err){
                if(err) { return next(err) }
                res.redirect("https://band-wagon-iota.vercel.app/login");
        })
})

app.put("/update-profile", authenticate, upload.single("profileImage"), async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ message: "Unauthorized. Please log in first." });
    }

    const { username, email } = req.body;

    if (!username || !email) {
      return res.status(400).json({ message: "All fields are required" });
    }

    let profileImage = req.user.profileImage;

    if (req.file) {
      try {
        const bufferStream = new Readable();
        bufferStream.push(req.file.buffer);
        bufferStream.push(null);

        const uploadResponse = await new Promise((resolve, reject) => {
          const uploadStream = cloudinary.v2.uploader.upload_stream(
            { folder: 'profiles' },
            (error, result) => {
              if (error) reject(error);
              else resolve(result);
            }
          );
          bufferStream.pipe(uploadStream);
        });

        if (uploadResponse && uploadResponse.secure_url) {
          profileImage = uploadResponse.secure_url;
        } else {
          throw new Error("Error uploading image to Cloudinary");
        }
      } catch (error) {
        throw new Error("Error uploading image to Cloudinary");
      }
    }

    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      {
        username,
        email,
        profileImage
      },
      { new: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json({ message: "User updated successfully", user: updatedUser });
  } catch (error) {
    console.error("Error updating user:", error.message);
    res.status(500).json({ message: "Internal server error" });
  }
});

        // Connect to MongoDB
// mongoose.connect(process.env.MONGODB_URL)
// .then(() => console.log("Connected to MongoDB"))
// .catch((error) => console.error("Error connecting to MongoDB:", error));
// Connect to MongoDB (per-request for serverless)

let cachedConnection = null;
async function connectDB() {
  if (cachedConnection) return cachedConnection;
  cachedConnection = await mongoose.createConnection(process.env.MONGODB_URL);
  console.log("Connected to MongoDB");
  return cachedConnection;
}
app.use(async (req, res, next) => { // Or call in routes
  await connectDB();
  next();
});

        // Routes
const userRoutes = require("./routes/user.routes.js");
// import { uploadOnCloudinary } from "./utils/cloudinary.js";
app.use("/api/user", userRoutes);

        // Google routes
// import googleRoutes from "./routes/auth.routes.js"
// import { access } from "fs";
// app.use("/auth", googleRoutes);
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: "Internal server error" });
});
        // Default route
app.get("/", (req, res) => {
    res.send("Backend is running...");  
})

        // Start the server
// const PORT = process.env.PORT || 5000;
// app.listen(PORT, () => {
//     console.log(`Server is running on port ${PORT}`);
// })
module.exports = app;