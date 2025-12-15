import { User } from "../generated/prisma/client";

export default function serializeUser(user: User) {
  const { id, email, username, googleId, emailConfirmed } = user;
  return { id, email, username, googleId, emailConfirmed };
}
