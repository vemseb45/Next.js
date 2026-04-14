import { prisma } from "@/lib/prisma";
import { NextResponse } from "next/server";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { z } from "zod";

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6),
});

export async function POST(req: Request) {
  try {
    const body = await req.json();

    // 1. Validar datos
    const data = loginSchema.parse(body);

    // 2. Buscar usuario
    const user = await prisma.user.findUnique({
      where: { email: data.email },
    });

    if (!user) {
      return NextResponse.json(
        { error: "Credenciales inválidas" },
        { status: 401 }
      );
    }

    // 3. Comparar password
    const isValid = await bcrypt.compare(data.password, user.password);

    if (!isValid) {
      return NextResponse.json(
        { error: "Credenciales inválidas" },
        { status: 401 }
      );
    }

    // 4. Crear JWT
    const token = jwt.sign(
      {
        userId: user.id,
        email: user.email,
        role: user.role,
      },
      process.env.NEXTAUTH_SECRET!,
      {
        expiresIn: "1h",
      }
    );

    // 5. Crear respuesta segura (sin password)

    const response = NextResponse.json({
      user: {
        name: user.name,
        email: user.email,
      },
    });

    // 6. Enviar token en cookie (MEJOR práctica)
    response.cookies.set("token", token, {
      httpOnly: true, // no accesible desde JS
      secure: false, // true en producción (HTTPS)
      sameSite: "strict",
      maxAge: 60 * 60, // 1 hora
      path: "/",
    });

    return response;
  } catch (error) {
    return NextResponse.json(
      { error: "Error en login" },
      { status: 500 }
    );
  }
}