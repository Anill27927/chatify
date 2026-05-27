import jwt from "jsonwebtoken";

export const generateToken = (userId, res) => {
  const token = jwt.sign({ userId }, process.env.JWT_SECRET, {
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
