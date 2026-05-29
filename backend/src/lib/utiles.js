import jwt from "jsonwebtoken";
import { ENV } from "./env.js";

export const generateToken = (userId, res) => {
  const { JWT_SECRET } = ENV;
  if (!JWT_SECRET) {
    throw new Error("JWT_SECRET is not defined in environment variables");
  }

  const token = jwt.sign({ userId }, JWT_SECRET, {
    expiresIn: "7d",
  });
  res.cookie("jwt", token, {
    httpOnly: true, // prevent xss attacks: cross site scripting
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    sameSite: "strict", // prevent csrf attacks: cross site request forgery
    secure: process.env.NODE_ENV === "development" ? false : true, // only send cookie over https in production
  });
  return token;
};
