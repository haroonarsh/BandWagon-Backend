import mongoose from "mongoose";

const showSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
    },
    image: {
        type: String,
        required: false,
    },
    date: {
        type: String,
        required: true,
    },
    startTime: {
        type: String,
        required: true,
    },
    endTime: {
        type: String,
        required: true,
    },
    latitude: {
        type: Number,
        required: false,
    },
    longitude: {
        type: Number,
        required: false,
    },
    location: {
        type: String,
        required: true,
    },
    bio: {
        type: String,
        required: true,
    },
    genres: {
        type: [String],
        enum: ['Blues', 'Classical', 'Country', 'EDM', 'Folk', 'Funk', 'Hip-Hop', 'Jazz', 'Latin', 'Metal', 'Pop', 'Punk', 'Reggae', 'R&B', 'Rock', 'Soul'],
        required: false,
    },
    artist: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Artist",
        required: true,
    },
},
   {
    timestamps: true
   } 
);

const Show = mongoose.models.Show || mongoose.model("Show", showSchema);

export default Show;