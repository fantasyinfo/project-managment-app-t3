import { hash, compare } from "bcryptjs";
import { z } from "zod";

import { createTRPCRouter, publicProcedure } from "~/server/api/trpc";

import { db } from "~/server/db";

export const userRouter = createTRPCRouter({
  register: publicProcedure
    .input(
      z.object({
        name: z.string(),
        username: z.string(),
        email: z.string().email(),
        password: z.string().min(6),
      }),
    )
    .mutation(async ({ input }) => {
      // extract body
      const { name, username, email, password } = input;

      // check unique email
      const existingUser = await db.user.findUnique({
        where: { email: email },
      });

      if (existingUser) {
        throw new Error("User already exists");
      }

      // check unique username
      const existingUsername = await db.user.findUnique({
        where: { username: username },
      });
      if (existingUsername) {
        throw new Error("Username already exists, try with another username.");
      }

      // hash the pass
      const hashedPassword = await hash(password, 10);

      // create the user
      return db.user.create({
        data: { name, username, email, password: hashedPassword },
      });
    }),

  login: publicProcedure
    .input(
      z.object({
        email: z.string().email(),
        password: z.string(),
      }),
    )
    .mutation(async ({ input }) => {
      const user = await db.user.findUnique({
        where: { email: input.email },
      });
      if (!user) throw new Error("User not found");

      const passwordMatch = await compare(input.password, user.password);
      if (!passwordMatch) throw new Error("Invalid password");

      return { message: "Login successful", user };
    }),
});
