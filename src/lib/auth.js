const User = require("../models/user.model");
const connectDB = require("../config/db");
const Credentials = require("next-auth/providers/credentials").default;
const bcrypt = require("bcryptjs");

export const authOptions = {
    provider: [
        Credentials({
            id: "credentials",
            name: "Credentials",
            credentials: {
                email: { label: "Email", type: "text" },
                password: { label: "Password", type: "password" }
            },
            async authorize(credentials) {
                await connectDB();
                const user = await User.findOne({ email: credentials?.email });
                if (!user) throw new Error("Wrong Email Credentials");
                const passwordMatch = await bcrypt.compare(
                    credentials.password,
                    user.password
                );

                if (!passwordMatch) throw new Error("Wrong Password Credentials");

                return user;
            },
        }),
    ],
    session: {
        strategy: "jwt",
    }
}